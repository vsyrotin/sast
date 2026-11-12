import argparse
import requests
import subprocess

def process_engagements(token_dojo, ci_project_id, ci_project_name,
                        ci_commit_tag, ci_project_url, severity,
                        scan_type, report_file, ci_project_namespace):
    """
    Выполняет действия, описанные в пайплайне для взаимодействия с Dojo.

    :param token_dojo: Токен для аутентификации в Dojo API
    :param ci_project_id: ID проекта
    :param ci_project_name: Название проекта
    :param ci_commit_tag: Текущий тег коммита
    :param ci_project_url: URL проекта в SCM
    :param severity: Минимальный уровень серьезности для скана
    :param scan_type: Тип сканирования
    :param report_file: Путь к файлу отчета для загрузки
    :param ci_project_namespace: Namespace проекта
    """
    base_url = "https://df/api/v2/"
    headers = {
        "authorization": f"Token {token_dojo}",
        "accept": "application/json",
        "content-type": "multipart/form-data"
    }

    print("Fetching engagements...")
    response = requests.get(f"{base_url}engagements/", headers=headers)
    response.raise_for_status()

    engagements = response.json()
    engagement_name = f"{ci_project_id}-{ci_project_name}"
    scan_action = "import-scan"

    scan_url = f"{base_url}{scan_action}/"
    with open(report_file, "rb") as f:
        curl_command = [
          "curl", "-X", "POST", "https://df/api/v2/import-scan/",
          "-H", f"Authorization: Token {token_dojo}",
          "-H", "accept: application/json",
          "-F", f"file=@{report_file}",
          "-F", f"active=true",
          "-F", f"branch_tag={ci_commit_tag}",
          "-F", f"source_code_management_uri={ci_project_url}/",
          "-F", f"minimum_severity={severity}",
          "-F", f"scan_type={scan_type}",
          "-F", f"product_name={ci_project_namespace}",
          "-F", f"product_type_name={ci_project_namespace}",
          "-F", f"engagement_name={engagement_name}",
          "-F", "auto_create_context=true",
          "-F", "verified=false",
          "-F", "create_finding_groups_for_all_findings=true",
          "-F", "group_by=component_name+component_version",
          "-F", "close_old_findings=yes",
          "-F", "push_to_jira=false"
         ]

        result = subprocess.run(curl_command, capture_output=True, text=True)

        if result.returncode == 0:
          print("Scan submitted successfully.")
        else:
          print(f"Error: {result.stderr}")

def run_command(command, env=None):
    """Run a shell command and print the output."""
    result = subprocess.run(command, shell=True, env=env, text=True, capture_output=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        raise Exception(f"Command failed with exit code {result.returncode}")

def run_checkov():
    run_command('checkov -d . --quiet --include-all-checkov-policies --run-all-external-checks --enable-secret-scan-all-files --deep-analysis -o sarif -s --output-file-path=. --download-external-modules true --external-modules-download-path external_modules > /dev/null')
    run_command('curl -o checkovSeverityParser.py https://raw.githubusercontent.com/vsyrotin/checkovParcer/refs/heads/main/parceJson.py')
    run_command('python3 checkovSeverityParser.py')
    process_engagements(
        token_dojo=args.dojo_token,
        ci_project_id=args.ci_project_id,
        ci_project_name=args.ci_project_name,
        ci_commit_tag=args.ci_commit_tag,
        ci_project_url=args.ci_project_url,
        severity="Low",
        scan_type="SARIF",
        report_file="result.sarif",
        ci_project_namespace=args.ci_project_namespace
    )

def run_gitleaks():
    run_command('curl -o gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml')
    run_command('gitleaks detect --exit-code 0 --source . --config=gitleaks.toml --max-target-megabytes 1000000000000000000 -f json -r gitleaks.json -v')
    process_engagements(
        token_dojo=args.dojo_token,
        ci_project_id=args.ci_project_id,
        ci_project_name=args.ci_project_name,
        ci_commit_tag=args.ci_commit_tag,
        ci_project_url=args.ci_project_url,
        severity="Low",
        scan_type="Gitleaks Scan",
        report_file="gitleaks.json",
        ci_project_namespace=args.ci_project_namespace
    )

def run_grype():
    run_command('grype --add-cpes-if-none . -o json > grype.json')
    process_engagements(
        token_dojo=args.dojo_token,
        ci_project_id=args.ci_project_id,
        ci_project_name=args.ci_project_name,
        ci_commit_tag=args.ci_commit_tag,
        ci_project_url=args.ci_project_url,
        severity="Low",
        scan_type="Anchore Grype",
        report_file="grype.json",
        ci_project_namespace=args.ci_project_namespace
    )

def run_semgrep():
    run_command('semgrep scan . --config=p/default --severity=WARNING --severity=ERROR --metrics=off --max-target-bytes 10000000000000 --no-git-ignore --json -o semgrep.json')
    process_engagements(
        token_dojo=args.dojo_token,
        ci_project_id=args.ci_project_id,
        ci_project_name=args.ci_project_name,
        ci_commit_tag=args.ci_commit_tag,
        ci_project_url=args.ci_project_url,
        severity="Low",
        scan_type="Semgrep JSON Report",
        report_file="semgrep.json",
        ci_project_namespace=args.ci_project_namespace
    )

def run_pipeline(args):
    run_checkov()
    run_gitleaks()
    run_grype()
    run_semgrep()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run the pipeline with parameters.')
    parser.add_argument('--dojo-token', type=str, required=True, help='Dojo token for quality gate')
    parser.add_argument('--ci-commit-tag', type=str, required=True, help='Current commit tag')
    parser.add_argument('--ci-project-url', type=str, required=True, help='Project URL')
    parser.add_argument('--ci-project-namespace', type=str, required=True, help='Project namespace')
    parser.add_argument('--ci-project-id', type=str, required=True, help='Project ID')
    parser.add_argument('--ci-project-name', type=str, required=True, help='Project name')

    args = parser.parse_args()
    print(args)
    try:
        run_pipeline(args)
    except Exception as e:
        print(f"Pipeline execution failed: {e}")
