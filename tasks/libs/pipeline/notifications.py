from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
from collections import defaultdict

import gitlab
import yaml
from gitlab.v4.objects import ProjectJob
from invoke.context import Context

from tasks.libs.ciproviders.gitlab_api import get_gitlab_repo
from tasks.libs.owners.parsing import read_owners
from tasks.libs.types.types import FailedJobReason, FailedJobs, Test


def load_and_validate(
    file_name: str, default_placeholder: str, default_value: str, relpath: bool = True
) -> dict[str, str]:
    if relpath:
        p = pathlib.Path(os.path.realpath(__file__)).parent.joinpath(file_name)
    else:
        p = pathlib.Path(file_name)

    result: dict[str, str] = {}
    with p.open(encoding='utf-8') as file_stream:
        for key, value in yaml.safe_load(file_stream).items():
            if not (isinstance(key, str) and isinstance(value, str)):
                raise ValueError(f"File {file_name} contains a non-string key or value. Key: {key}, Value: {value}")
            result[key] = default_value if value == default_placeholder else value
    return result


DATADOG_AGENT_GITHUB_ORG_URL = "https://github.com/DataDog"
DEFAULT_SLACK_CHANNEL = "#agent-developer-experience"
DEFAULT_JIRA_PROJECT = "AGNTR"
# Map keys in lowercase
GITHUB_SLACK_MAP = load_and_validate("github_slack_map.yaml", "DEFAULT_SLACK_CHANNEL", DEFAULT_SLACK_CHANNEL)
GITHUB_JIRA_MAP = load_and_validate("github_jira_map.yaml", "DEFAULT_JIRA_PROJECT", DEFAULT_JIRA_PROJECT)


def check_for_missing_owners_slack_and_jira(print_missing_teams=True, owners_file=".github/CODEOWNERS"):
    owners = read_owners(owners_file)
    error = False
    for path in owners.paths:
        if not path[2] or path[2][0][0] != "TEAM":
            continue
        if path[2][0][1].lower() not in GITHUB_SLACK_MAP:
            error = True
            if print_missing_teams:
                print(f"The team {path[2][0][1]} doesn't have a slack team assigned !!")
        if path[2][0][1].lower() not in GITHUB_JIRA_MAP:
            error = True
            if print_missing_teams:
                print(f"The team {path[2][0][1]} doesn't have a jira project assigned !!")
    return error


def get_failed_tests(project_name, job: ProjectJob, owners_file=".github/CODEOWNERS"):
    repo = get_gitlab_repo(project_name)
    owners = read_owners(owners_file)
    try:
        test_output = str(repo.jobs.get(job.id, lazy=True).artifact('test_output.json'), 'utf-8')
    except gitlab.exceptions.GitlabGetError:
        test_output = ''
    failed_tests = {}  # type: dict[tuple[str, str], Test]
    if test_output:
        for line in test_output.splitlines():
            json_test = json.loads(line)
            if 'Test' in json_test:
                name = json_test['Test']
                package = json_test['Package']
                action = json_test["Action"]

                if action == "fail":
                    # Ignore subtests, only the parent test should be reported for now
                    # to avoid multiple reports on the same test
                    # NTH: maybe the Test object should be more flexible to incorporate
                    # subtests? This would require some postprocessing of the Test objects
                    # we yield here to merge child Test objects with their parents.
                    if '/' in name:  # Subtests have a name of the form "Test/Subtest"
                        continue
                    failed_tests[(package, name)] = Test(owners, name, package)
                elif action == "pass" and (package, name) in failed_tests:
                    print(f"Test {name} from package {package} passed after retry, removing from output")
                    del failed_tests[(package, name)]

    return failed_tests.values()


def find_job_owners(failed_jobs: FailedJobs, owners_file: str = ".gitlab/JOBOWNERS") -> dict[str, FailedJobs]:
    owners = read_owners(owners_file)
    owners_to_notify = defaultdict(FailedJobs)
    # For e2e test infrastructure errors, notify the agent-e2e-testing team
    for job in failed_jobs.mandatory_infra_job_failures:
        if job.failure_reason == FailedJobReason.E2E_INFRA_FAILURE:
            owners_to_notify["@DataDog/agent-e2e-testing"].add_failed_job(job)

    for job in failed_jobs.all_non_infra_failures():
        job_owners = owners.of(job.name)
        # job_owners is a list of tuples containing the type of owner (eg. USERNAME, TEAM) and the name of the owner
        # eg. [('TEAM', '@DataDog/agent-ci-experience')]

        for kind, owner in job_owners:
            if kind == "TEAM":
                owners_to_notify[owner].add_failed_job(job)

    return owners_to_notify


def get_pr_from_commit(commit_title, project_title) -> tuple[str, str] | None:
    parsed_pr_id_found = re.search(r'.*\(#([0-9]*)\)$', commit_title)
    if not parsed_pr_id_found:
        return None

    parsed_pr_id = parsed_pr_id_found.group(1)

    return parsed_pr_id, f"{DATADOG_AGENT_GITHUB_ORG_URL}/{project_title}/pull/{parsed_pr_id}"


def base_message(header, state):
    project_title = os.getenv("CI_PROJECT_TITLE")
    # commit_title needs a default string value, otherwise the re.search line below crashes
    commit_title = os.getenv("CI_COMMIT_TITLE", "")
    pipeline_url = os.getenv("CI_PIPELINE_URL")
    pipeline_id = os.getenv("CI_PIPELINE_ID")
    commit_ref_name = os.getenv("CI_COMMIT_REF_NAME")
    commit_url_gitlab = f"{os.getenv('CI_PROJECT_URL')}/commit/{os.getenv('CI_COMMIT_SHA')}"
    commit_url_github = f"{DATADOG_AGENT_GITHUB_ORG_URL}/{project_title}/commit/{os.getenv('CI_COMMIT_SHA')}"
    commit_short_sha = os.getenv("CI_COMMIT_SHORT_SHA")
    author = get_git_author()

    # Try to find a PR id (e.g #12345) in the commit title and add a link to it in the message if found.
    pr_info = get_pr_from_commit(commit_title, project_title)
    enhanced_commit_title = commit_title
    if pr_info:
        parsed_pr_id, pr_url_github = pr_info
        enhanced_commit_title = enhanced_commit_title.replace(f"#{parsed_pr_id}", f"<{pr_url_github}|#{parsed_pr_id}>")

    return f"""{header} pipeline <{pipeline_url}|{pipeline_id}> for {commit_ref_name} {state}.
{enhanced_commit_title} (<{commit_url_gitlab}|{commit_short_sha}>)(:github: <{commit_url_github}|link>) by {author}"""


def get_git_author(email=False):
    format = 'ae' if email else 'an'

    return (
        subprocess.check_output(["git", "show", "-s", f"--format='%{format}'", "HEAD"])
        .decode('utf-8')
        .strip()
        .replace("'", "")
    )


def send_slack_message(recipient, message):
    subprocess.run(["postmessage", recipient, message], check=True)


def email_to_slackid(ctx: Context, email: str) -> str:
    slackid = ctx.run(f"echo '{email}' | email2slackid", hide=True, warn=True).stdout.strip()

    assert slackid != '', 'Email not found'

    return slackid
