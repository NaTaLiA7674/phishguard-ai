import json
import os
import sys
import glob
import logging
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, SRC_DIR)

from src.level2_agent.models import (
    EmailData, PhishingReport,
    SEVERIDAD_BAJO, SEVERIDAD_MEDIO, SEVERIDAD_ALTO, SEVERIDAD_CRITICO,
)
from src.level2_agent.agent import analyze_email, _genetic_score

PASS = "PASS"
FAIL = "FAIL"

results = []


def load_fixtures(fixtures_dir: str) -> list[dict]:
    fixtures = []
    pattern = os.path.join(fixtures_dir, "*.json")
    for path in sorted(glob.glob(pattern)):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        _test = data.pop("_test")
        data["_test"] = _test
        fixtures.append(data)
    return fixtures


def validate_fixture(data: dict) -> tuple[str, str]:
    try:
        email_data = EmailData.model_validate(data)
        return "ok", email_data
    except Exception as e:
        return "error", str(e)


def detect_route(genetic_result: dict, report: PhishingReport) -> str:
    score = genetic_result["score"]
    if score < 30:
        return "benign"
    if score > 75:
        return "malicious"
    if not report.es_phishing:
        return "ai_agent_safe"
    return "ai_agent_malicious"


def validate_report_structure(report: PhishingReport) -> list[str]:
    errors = []
    required_fields = [
        "resumen", "analisis_tecnico", "indicadores_phishing",
        "es_phishing", "nivel_severidad", "justificacion_veredicto",
    ]
    for field in required_fields:
        if not hasattr(report, field):
            errors.append(f"Falta el campo: {field}")
            continue
        val = getattr(report, field)
        if field == "indicadores_phishing" and not isinstance(val, list):
            errors.append(f"{field} deberia ser lista, es {type(val).__name__}")
        elif field == "es_phishing" and not isinstance(val, bool):
            errors.append(f"{field} deberia ser bool, es {type(val).__name__}")
        elif field in ("nivel_severidad",) and val not in (SEVERIDAD_BAJO, SEVERIDAD_MEDIO, SEVERIDAD_ALTO, SEVERIDAD_CRITICO):
            errors.append(f"{field}='{val}' no es un valor valido")
    return errors


def check_score_bounds(score: float, meta: dict) -> tuple[str, str]:
    min_s = meta.get("expected_score_min", -float("inf"))
    max_s = meta.get("expected_score_max", float("inf"))
    if score < min_s:
        return FAIL, f"Score {score:.2f} < minimo {min_s}"
    if score > max_s:
        return FAIL, f"Score {score:.2f} > maximo {max_s}"
    return PASS, f"Score {score:.2f} en rango [{min_s}, {max_s}]"


def check_route(actual: str, expected: str) -> tuple[str, str]:
    if actual == expected:
        return PASS, f"Ruta correcta: {actual}"
    return FAIL, f"Ruta esperada: {expected}, obtenida: {actual}"


def run_test_case(fixture: dict, index: int, total: int) -> dict:
    meta = fixture["_test"]
    name = meta["name"]
    print(f"\n--- [{index}/{total}] {name} " + "-" * 40)

    status, email_or_err = validate_fixture(fixture)
    if status == "error":
        print(f"  Error validando fixture: {email_or_err}")
        return {"name": name, "route": "ERROR", "score": None, "status": FAIL, "details": str(email_or_err)}

    email_data = email_or_err
    print(f"  Asunto: {email_data.subject}")
    print(f"  Destinatario: {email_data.recipient}")

    genetic_result = _genetic_score(email_data)
    score = genetic_result["score"]
    print(f"  Score genetico: {score:.2f}")

    score_status, score_detail = check_score_bounds(score, meta)
    print(f"  [{score_status}] Score: {score_detail}")

    try:
        report = analyze_email(email_data)
    except Exception as e:
        print(f"  [{FAIL}] analyze_email() lanza excepcion: {e}")
        return {"name": name, "route": "ERROR", "score": score, "status": FAIL, "details": str(e)}

    route = detect_route(genetic_result, report)
    expected_route = meta.get("expected_route", "?")
    route_status, route_detail = check_route(route, expected_route)
    print(f"  [{route_status}] Ruta: {route_detail}")

    struct_errors = validate_report_structure(report)
    if struct_errors:
        for err in struct_errors:
            print(f"  [{FAIL}] Estructura: {err}")
    else:
        print(f"  [{PASS}] Estructura del reporte valida")

    veredicto = "PHISHING" if report.es_phishing else "SEGURO"
    print(f"  Veredicto: {veredicto} | Severidad: {report.nivel_severidad}")

    if report.es_phishing:
        inds = ", ".join(report.indicadores_phishing[:5])
        if len(report.indicadores_phishing) > 5:
            inds += "..."
        print(f"  Indicadores: {inds}")

    all_ok = (score_status == PASS and route_status == PASS and not struct_errors)
    overall = PASS if all_ok else FAIL

    return {
        "name": name,
        "route": route,
        "score": score,
        "status": overall,
        "details": f"Score {score:.2f}, ruta={route}",
    }


def print_summary(results: list[dict]):
    print("\n")
    print("=" * 60)
    print("            RESUMEN DE PRUEBAS")
    print("=" * 60)
    print(f"{'Caso':<20} {'Ruta':<25} {'Score':<8} {'Estado':<8}")
    print("-" * 60)
    passed = 0
    for r in results:
        score_str = f"{r['score']:.2f}" if r['score'] is not None else "N/A"
        status_display = PASS if r['status'] == PASS else FAIL
        print(f"{r['name']:<20} {r['route']:<25} {score_str:<8} {status_display:<8}")
        if r['status'] != PASS:
            print(f"{'':>20} Detalles: {r['details']}")
        if r['status'] == PASS:
            passed += 1
    print("-" * 60)
    print(f"Total: {len(results)} | Pasaron: {passed} | Fallaron: {len(results) - passed}")
    print("=" * 60 + "\n")
    return passed == len(results)


def main():
    fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")

    if not os.path.isdir(fixtures_dir):
        print(f"ERROR: No se encuentra el directorio de fixtures: {fixtures_dir}")
        sys.exit(1)

    fixtures = load_fixtures(fixtures_dir)
    if not fixtures:
        print(f"ERROR: No se encontraron fixtures JSON en {fixtures_dir}")
        sys.exit(1)

    total = len(fixtures)
    print(f"Cargados {total} fixtures:")
    for f in fixtures:
        meta = f["_test"]
        desc = meta.get("description", "sin descripcion")
        print(f"  * {meta['name']}: {desc}")

    all_results = []
    for i, fixture in enumerate(fixtures, 1):
        result = run_test_case(fixture, i, total)
        all_results.append(result)

    all_pass = print_summary(all_results)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
