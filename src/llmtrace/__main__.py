import os
import click

from dataset.dataset import Dataset
from lib.clean_new_data import clean_new_data
from llm_eval.llm_eval import LLM_Evaluator
from scraper.scraper import Scraper

@click.group()
def llmtrace():
    click.echo("--------------------")
    click.echo("     LlmTrace")
    click.echo("--------------------")

@llmtrace.command()
def scrape():
    click.echo("Scraping")
    scraper = Scraper()
    scraper.download_captures()

@llmtrace.command()
def clean_raw():
    click.echo("Cleaning raw data")
    clean_raw_data()

@llmtrace.command()
def scrape_and_clean():
    click.echo("Scraping and cleaning raw data")
    #scraper = Scraper()
    #scraper.download_captures()
    clean_raw_data()
    #clean_new_data()

@llmtrace.command()
@click.option("--data_path", default="data/cleaned", help="Path to the data folder")
@click.option(
    "--zero_shot",
    is_flag=True,
    default=True,
    show_default=True,
    help="Generate zero shot dataset",
)
@llmtrace.command()
@click.option("--input_file", default="alert.ids", help="Archivo de alertas Snort para parsear")
@click.option("--output_file", default="alerts.json", help="Archivo JSON de salida")
def parser(input_file, output_file):
    click.echo(f"Parsing Snort alerts from {input_file}...")
    try:
        alerts = parse_snort_alerts(input_file)
        save_to_json(alerts, output_file)
        click.echo(f"Alerts saved to {output_file}")
        click.echo(f"Total alerts parsed: {len(alerts)}")
    except FileNotFoundError:
        click.echo(f"Error: {input_file} not found.")
    except Exception as e:
        click.echo(f"Error parsing file: {e}")
@click.option(
    "--one_shot", is_flag=True, default=False, help="Generate one shot dataset"
)
@click.option(
    "--chain_of_thought",
    is_flag=True,
    default=False,
    help="Generate chain-of-thought dataset",
)
def generate_dataset(data_path, zero_shot, one_shot, chain_of_thought):
    click.echo("Generating dataset")
    dataset = Dataset(os.path.join(os.getcwd(), data_path))
    capture_example = '''[
        {
            "sid": "527",
            "generator_id": "1",
            "revision": "8",
            "message": "BAD-TRAFFIC same SRC/DST",
            "classification": "Potentially Bad Traffic",
            "priority": 2,
            "timestamp": "05/30-19:09:10.917356",
            "source_ip": "0.0.0.0",
            "source_port": 68,
            "destination_ip": "255.255.255.255",
            "destination_port": 67,
            "protocol": "UDP",
            "ttl": 128,
            "tos": "0x0",
            "id": 0,
            "ip_length": 20,
            "datagram_length": 328,
            "payload_length": 300,
            "references": []
        },
        {
            "sid": "527",
            "generator_id": "1",
            "revision": "8",
            "message": "BAD-TRAFFIC same SRC/DST",
            "classification": "Potentially Bad Traffic",
            "priority": 2,
            "timestamp": "05/30-19:09:10.918155",
            "source_ip": "0.0.0.0",
            "source_port": 68,
            "destination_ip": "255.255.255.255",
            "destination_port": 67,
            "protocol": "UDP",
            "ttl": 128,
            "tos": "0x0",
            "id": 1,
            "ip_length": 20,
            "datagram_length": 354,
            "payload_length": 326,
            "references": []
        },
        {
            "sid": "2014895",
            "generator_id": "1",
            "revision": "5",
            "message": "ET CURRENT_EVENTS RedKit - Landing Page Received",
            "classification": "A Network Trojan was Detected",
            "priority": 1,
            "timestamp": "05/30-19:09:10.927356",
            "source_ip": "188.72.248.160",
            "source_port": 80,
            "destination_ip": "192.168.88.10",
            "destination_port": 80,
            "protocol": "TCP",
            "ttl": 54,
            "tos": "0x0",
            "id": 15975,
            "ip_length": 20,
            "datagram_length": 714,
            "payload_length": null,
            "references": ["http://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-4681"]
        },
        {
            "sid": "2012811",
            "generator_id": "1",
            "revision": "2",
            "message": "ET DNS DNS Query to a .tk domain",
            "classification": "Potentially Bad Traffic",
            "priority": 2,
            "timestamp": "05/30-19:09:11.917356",
            "source_ip": "192.168.88.10",
            "source_port": 1029,
            "destination_ip": "4.2.2.3",
            "destination_port": 53,
            "protocol": "UDP",
            "ttl": 128,
            "tos": "0x0",
            "id": 78,
            "ip_length": 20,
            "datagram_length": 59,
            "payload_length": 31,
            "references": []
        }
    ]'''
    questions = dataset.get_questions()

    if one_shot:
        click.echo("##############################")
        click.echo("Generating one shot dataset")
        click.echo("##############################")
        dataset.generate_dataset(
            "one_shot",
            [
                f"{capture_example}\nQ: {questions[0]}\nA: In the file there are a total of 4 alerts.",
                f"{capture_example}\nQ: {questions[1]}\nA: The most frequent classification is Potentially Bad Traffic with 3 occurrences.",
                f"{capture_example}\nQ: {questions[2]}\nA: Public IP addresses are more frequent as the destination in the alerts with 3 occurrences.",
                f"{capture_example}\nQ: {questions[3]}\nA: The average datagram length is 363.75 bytes across 4 valid alerts.",
                f"{capture_example}\nQ: {questions[4]}\nA: There are 1 alerts with high priority (priority 1).",
                f"{capture_example}\nQ: {questions[5]}\nA: No source IPs with multiple classifications found in 1 minute.",
                f"{capture_example}\nQ: {questions[6]}\nA: 1 alerts with CVE references targeting vulnerable ports: Alert SID 2014895 (ID 15975, port 80, message: ET CURRENT_EVENTS RedKit - Landing Page Received).",
                f"{capture_example}\nQ: {questions[7]}\nA: Top destination ports: 67 (50.00%, 2 alerts), 80 (25.00%, 1 alerts), 53 (25.00%, 1 alerts).",
                f"{capture_example}\nQ: {questions[8]}\nA: Source IPs with focused attack attempts: 0.0.0.0: 2 alerts targeting 255.255.255.255 in 0.00s.",
            ],
        )
    elif chain_of_thought:
        click.echo("##############################")
        click.echo("Generating Chain-of-Thought dataset")
        click.echo("##############################")
        dataset.generate_dataset(
            "chain_of_thought",
            [
                f"{capture_example}\nQ: {questions[0]}\nA: The JSON array contains 4 alert entries. Thus, the total number of alerts is 4.",
                f"{capture_example}\nQ: {questions[1]}\nA: Classifications: Alert 1: Potentially Bad Traffic, Alert 2: Potentially Bad Traffic, Alert 3: A Network Trojan was Detected, Alert 4: Potentially Bad Traffic. Counts: Potentially Bad Traffic (3), A Network Trojan was Detected (1). The most annoying classification is Potentially Bad Traffic with 3 occurrences.",
                f"{capture_example}\nQ: {questions[2]}\nA: Destination IPs: Alert 1: 255.255.255.255 (public), Alert 2: 255.255.255.255 (public), Alert 3: 192.168.88.10 (private), Alert 4: 4.2.2.3 (public). Public: 3, Private: 1. Public IP addresses are more frequent with 3 occurrences.",
                f"{capture_example}\nQ: {questions[3]}\nA: Datagram lengths: Alert 1: 328 bytes, Alert 2: 354 bytes, Alert 3: 714 bytes, Alert 4: 59 bytes. Total = 328 + 354 + 714 + 59 = 1455 bytes. Average = 1455 / 4 = 363.75 bytes.",
                f"{capture_example}\nQ: {questions[4]}\nA: Priorities: Alert 1: 2, Alert 2: 2, Alert 3: 1, Alert 4: 2. Only Alert 3 has priority 1. Thus, there are 1 alerts with high priority (priority 1).",
                f"{capture_example}\nQ: {questions[5]}\nA: Source IPs: 0.0.0.0 (Potentially Bad Traffic, 2x), 188.72.248.160 (A Network Trojan), 192.168.88.10 (Potentially Bad Traffic). Timestamps are within ~1s (< 60s). No source IP has multiple classifications. Thus, no source IPs with multiple classifications found.",
                f"{capture_example}\nQ: {questions[6]}\nA: Vulnerable ports: 80, 443, 445. Alert 1: port 67, no CVE. Alert 2: port 67, no CVE. Alert 3: port 80, has CVE-2012-4681. Alert 4: port 53, no CVE. One alert meets the criteria: SID 2014895 (ID 15975, port 80, message: ET CURRENT_EVENTS RedKit - Landing Page Received).",
                f"{capture_example}\nQ: {questions[7]}\nA: Ports: Alert 1: 67, Alert 2: 67, Alert 3: 80, Alert 4: 53. Counts: 67 (2), 80 (1), 53 (1). Total alerts: 4. Percentages: 67 (50.00%), 80 (25.00%), 53 (25.00%). Thus, ports: 67 (50.00%, 2 alerts), 80 (25.00%, 1 alerts), 53 (25.00%, 1 alerts).",
                f"{capture_example}\nQ: {questions[8]}\nA: Pairs: (0.0.0.0, 255.255.255.255): 2 alerts (timestamps 19:09:10.917356, 19:09:10.918155, Δt ≈ 0.000799s), (188.72.248.160, 192.168.88.10): 1 alert, (192.168.88.10, 4.2.2.3): 1 alert. The pair (0.0.0.0, 255.255.255.255) has 2 alerts within 30 seconds. Thus, 0.0.0.0: 2 alerts targeting 255.255.255.255 in 0.00s."
            ],
        )
    else:
        click.echo("##############################")
        click.echo("Generating zero shot dataset")
        click.echo("##############################")
        dataset.generate_dataset(
            "zero_shot",
            10 * [""],
        )
    

@llmtrace.command()
@click.option("--model", default="llama2", help="Model to evaluate")
@click.option(
    "--dataset_path", default="data/zero_shot/dataset.jsonl", help="Path to the dataset"
)
@click.option(
    "--output_path",
    default="data/evaluation/generated_output_llama2.jsonl",
    help="Path to the generated output file",
)
def answer_questions(model, dataset_path, output_path):
    click.echo(f"Answering questions for model: {model}")
    evaluator = LLM_Evaluator(model_to_eval=model, dataset_path=dataset_path)
    evaluator.answer_questions(output_path=output_path)

@llmtrace.command()
@click.option(
    "--generated_output",
    default="data/evaluation/generated_output_llama2.jsonl",
    help="Path to the generated output file",
)
@click.option(
    "--dataset_path",
    default="data/zero_shot/dataset.jsonl",
    help="Path to the dataset",
)
def evaluate(generated_output, dataset_path):
    click.echo("Generating report")
    model = generated_output.split("/")[-1].split("_")[-1].split(".")[0]
    evaluator = LLM_Evaluator(model_to_eval=model, dataset_path=dataset_path)
    evaluator.evaluate_model(generated_output_path=generated_output)

@llmtrace.command()
@click.option(
    "--evaluation_input", default="data/evaluation/generated_output_llama2.jsonl"
)
def generate_report(evaluation_input):
    model = evaluation_input.split("/")[-1].split("_")[-1].split(".")[0]
    click.echo(f"Generating report for model: {model}")
    evaluator = LLM_Evaluator(model_to_eval=model)
    evaluator.generate_report(evaluation_input)

if __name__ == "__main__":
    llmtrace()
