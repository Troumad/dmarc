#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extraction des IP posant problème depuis des rapports DMARC.

Parcourt tous les fichiers .zip et .gz (et .xml) du répertoire courant,
détecte les enregistrements en échec DKIM ou SPF, puis produit
"ip_probleme.csv" avec, par IP :
  - l'adresse IP
  - le propriétaire (WHOIS)
  - le type de problème (dkim et/ou spf)
  - le nombre de messages concernés
  - l'origine du problème (organisations ayant signalé l'IP)
"""

import argparse
import csv
import glob
import gzip
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
import zipfile

OUTPUT_FILE = "ip_probleme.csv"
WHOIS_TIMEOUT = 10


def iter_report_files():
    """Renvoie la liste des fichiers zip / gz / xml du répertoire courant."""
    files = []
    for pattern in ("*.zip", "*.gz", "*.xml"):
        files.extend(sorted(glob.glob(pattern)))
    return files


def read_xml_from_file(path):
    """Extrait le contenu XML d'un fichier zip, gz ou xml.

    Renvoie une liste de chaînes XML (un zip peut contenir plusieurs rapports).
    """
    contents = []
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.lower().endswith(".xml"):
                    with archive.open(name) as member:
                        contents.append(member.read())
    elif path.lower().endswith(".gz"):
        with gzip.open(path, "rb") as archive:
            contents.append(archive.read())
    elif path.lower().endswith(".xml"):
        with open(path, "rb") as fichier:
            contents.append(fichier.read())
    return contents


def whois_query(server, query):
    """Effectue une requête WHOIS sur le serveur donné."""
    try:
        with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as sock:
            sock.sendall(query.encode() + b"\r\n")
            morceaux = []
            while True:
                bloc = sock.recv(4096)
                if not bloc:
                    break
                morceaux.append(bloc)
            return b"".join(morceaux).decode("utf-8", errors="replace")
    except (OSError, socket.timeout):
        return ""


_CLE_ORG_RE = re.compile(r"^(netname|org-name|orgname|organization|owner|descr|resourcename)", re.IGNORECASE)
_REFERAL_RE = re.compile(r"^refer:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def lookup_ip_owner(ip, cache):
    """Retourne le nom du propriétaire de l'IP via WHOIS (avec cache)."""
    if ip in cache:
        return cache[ip]
    reponse = whois_query("whois.iana.org", ip)
    referral_match = _REFERAL_RE.search(reponse)
    if not referral_match:
        cache[ip] = "inconnu"
        return "inconnu"
    serveur_registre = referral_match.group(1)
    reponse = whois_query(serveur_registre, ip)
    nom = "inconnu"
    for ligne in reponse.splitlines():
        if _CLE_ORG_RE.match(ligne.strip()):
            valeur = ligne.split(":", 1)[1].strip()
            if valeur:
                nom = valeur
                break
    cache[ip] = nom
    return nom


def extraire_report_id(xml_bytes):
    """Renvoie le report_id d'un rapport DMARC, ou None si absent/illisible."""
    try:
        racine = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    report_id = (racine.findtext("./report_metadata/report_id") or "").strip()
    return report_id or None


def renommer_rapports(fichiers):
    """Renomme les rapports en expéditeur!domaine!début!fin!report_id.ext.

    Évite les collisions : les rapports Google/Microsoft d'une même journée
    partagent le même nom de fichier alors que leur report_id diffère.
    """
    renommes = 0
    for path in fichiers:
        for xml_bytes in read_xml_from_file(path):
            report_id = extraire_report_id(xml_bytes)
            if not report_id:
                continue
            report_id_propre = re.sub(r"[!/:\*\?\"<>|]+", "_", report_id)
            if path.lower().endswith(".xml.gz"):
                base, ext = path[:-7], ".xml.gz"
            else:
                base, ext = os.path.splitext(path)
            nouveau_nom = f"{base}!{report_id_propre}{ext}"
            if nouveau_nom == path or os.path.exists(nouveau_nom):
                continue
            os.rename(path, nouveau_nom)
            renommes += 1
            print(f"{path} -> {os.path.basename(nouveau_nom)}")
            break
    if renommes:
        print(f"{renommes} fichier(s) renommé(s).")


def extraire_report_id(xml_bytes):
    """Renvoie le report_id d'un rapport DMARC, ou None si absent/illisible."""
    try:
        racine = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    report_id = (racine.findtext("./report_metadata/report_id") or "").strip()
    return report_id or None


def extract_problems_from_xml(xml_bytes, problems):
    """Analyse un rapport DMARC et agrège les échecs DKIM/SPF par IP."""
    try:
        racine = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return
    org_name = (racine.findtext("./report_metadata/org_name") or "").strip() or "inconnu"
    for record in racine.iter("record"):
        source_ip_el = record.find("./row/source_ip")
        if source_ip_el is None or not (source_ip_el.text or "").strip():
            continue
        ip = source_ip_el.text.strip()
        row = record.find("./row")
        count_el = row.find("count") if row is not None else None
        try:
            nb = int((count_el.text or "1").strip())
        except ValueError:
            nb = 1
        types_problemes = set()
        dkim_eval = (record.findtext("./row/policy_evaluated/dkim") or "").strip().lower()
        spf_eval = (record.findtext("./row/policy_evaluated/spf") or "").strip().lower()
        if dkim_eval == "fail":
            types_problemes.add("dkim")
        if spf_eval == "fail":
            types_problemes.add("spf")
        for result in record.findall("./auth_results/dkim"):
            if (result.findtext("result") or "").strip().lower() == "fail":
                types_problemes.add("dkim")
        for result in record.findall("./auth_results/spf"):
            if (result.findtext("result") or "").strip().lower() == "fail":
                types_problemes.add("spf")
        if not types_problemes:
            continue
        entree = problems.setdefault(ip, {"dkim": 0, "spf": 0, "messages": 0, "origines": []})
        if "dkim" in types_problemes:
            entree["dkim"] += nb
        if "spf" in types_problemes:
            entree["spf"] += nb
        entree["messages"] += nb
        if org_name not in entree["origines"]:
            entree["origines"].append(org_name)
        report_id = (racine.findtext("./report_metadata/report_id") or "").strip()
        if report_id:
            entree.setdefault("report_ids", set()).add(report_id)


def main():
    parser = argparse.ArgumentParser(description="Extraction des IP problématiques des rapports DMARC.")
    parser.add_argument("--renommer", action="store_true", help="renommer les rapports en ajoutant le report_id au nom de fichier")
    args = parser.parse_args()
    fichiers = iter_report_files()
    if not fichiers:
        print("Aucun fichier zip/gz/xml trouvé dans le répertoire courant.")
        return 1
    if args.renommer:
        renommer_rapports(fichiers)
        fichiers = iter_report_files()
    problems = {}
    report_ids_vus = set()
    rapports_ignore = 0
    for path in fichiers:
        for xml_bytes in read_xml_from_file(path):
            report_id = extraire_report_id(xml_bytes)
            if report_id and report_id in report_ids_vus:
                rapports_ignore += 1
                continue
            if report_id:
                report_ids_vus.add(report_id)
            extract_problems_from_xml(xml_bytes, problems)
    if rapports_ignore:
        print(f"{rapports_ignore} rapport(s) en double ignoré(s).")
    if not problems:
        print("Aucune IP en échec DKIM/SPF détectée : pas de fichier généré.")
        return 0
    cache_whois = {}
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as sortie:
        writer = csv.writer(sortie)
        writer.writerow(["ip", "proprietaire", "probleme", "nombre", "origine"])
        for ip in sorted(problems):
            types = [t for t in ("dkim", "spf") if problems[ip][t] > 0]
            nombre = problems[ip]["messages"]
            proprietaire = lookup_ip_owner(ip, cache_whois)
            origine = " + ".join(problems[ip]["origines"])
            writer.writerow([ip, proprietaire, " et ".join(types), nombre, origine])
    print(f"{len(problems)} IP problématiques écrites dans {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
