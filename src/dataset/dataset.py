import json
import os
import re
from datetime import datetime
from subprocess import check_output
import ipaddress

class Dataset:
    def __init__(self, data_path: str):
        self.__questions = [
            "What is the total number of alerts?",
            "What is the most frequent alert classification and how many times does it appear?",
            "In the alerts, which type of destination IP address is more frequent: private or public?",
            "What is the average datagram length across all alerts?",
            "How many alerts are classified as having the highest priority level?", 
            "Which source IP addresses are associated with multiple alert classifications within a 1-minute time window?",
            "Which alerts have references to CVEs in their 'references' field and target ports commonly associated with vulnerable services (e.g., 80, 443, 445)?",
            "Which destination ports are targeted most frequently, and what percentage of alerts do they represent?",
            "Which source IP addresses generate multiple alerts targeting the same destination IP within a 30-second window, indicating focused attack attempts?",
        ]
        #ip involucrada en alerta alta
        #ip que se repite o varias en alerta alta
        if os.path.exists(os.path.join(os.getcwd(), data_path)):
            self.__data_path = data_path
            self.__files = self.__get_files(data_path)
        else:
            raise Exception("The path is not valid")

    def answer_questions_for_alerts(self, file: str) -> dict:
        """Answers predefined questions about Snort JSON alerts."""
        if not file.endswith('.json'):
            raise ValueError("File must be a .json file")
        
        with open(os.path.join(self.__data_path, file), 'r') as f:
            snort_alerts = json.load(f)
        quest_sol = {}
        num_alerts = len(snort_alerts)

        

        def is_private_ip(ip) -> bool:
            """
            Check if the IP address is private according to RFC 1918.
            Returns False for invalid, None or non-IPv4 addresses.
            """
            if not isinstance(ip, str):
                return False

            ip = ip.strip()
            if not ip:
                return False

            # Validar IPv4 usando módulo estándar ipaddress
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                return ip_obj.is_private
            except ipaddress.AddressValueError:
                # No es IPv4 válida
                return False


        def parse_timestamp(ts: str) -> float:
            """Convert timestamp 'MM/DD-HH:MM:SS.ssssss' to seconds since epoch."""
            try:
                dt = datetime.strptime(ts, "%m/%d-%H:%M:%S.%f")
                return dt.timestamp()
            except (ValueError, TypeError):
                return 0.0

        for i, question in enumerate(self.__questions):
            if i == 0:
                quest_sol[question] = (
                    f"In the file there are a total of {num_alerts} alerts."
                )
            elif i == 1:
                count_classification = {}
                for alert in snort_alerts:
                    classification = alert.get("classification", "Unknown")
                    count_classification[classification] = count_classification.get(classification, 0) + 1
                if not count_classification:
                    quest_sol[question] = "No classifications found in the alerts."
                else:
                    most_common_classification = max(count_classification, key=count_classification.get)
                    quest_sol[question] = (
                        f"The most annoying classification is {most_common_classification} with {count_classification[most_common_classification]} occurrences."
                    )
            elif i == 2:
                private_count = 0
                public_count = 0
                for alert in snort_alerts:
                    dest_ip = alert.get("destination_ip", "")
                    if is_private_ip(dest_ip):
                        private_count += 1
                    else:
                        public_count += 1
                if private_count > public_count:
                    quest_sol[question] = (
                        f"Private IP addresses are more frequent as the destination in the alerts with {private_count} occurrences."
                    )
                elif public_count > private_count:
                    quest_sol[question] = (
                        f"Public IP addresses are more frequent as the destination in the alerts with {public_count} occurrences."
                    )
                else:
                    quest_sol[question] = (
                        f"Private and public IP addresses are equally frequent as the destination in the alerts with {private_count} occurrences."
                    )
            elif i == 3:
                total_length = 0
                valid_count = 0
                for alert in snort_alerts:
                    datagram_length = alert.get("datagram_length")
                    if datagram_length is not None and isinstance(datagram_length, (int, float)) and datagram_length >= 0:
                        total_length += datagram_length
                        valid_count += 1
                if valid_count > 0:
                    average_length = total_length / valid_count
                    quest_sol[question] = (
                        f"The average datagram length is {average_length:.2f} bytes across {valid_count} valid alerts."
                    )
                else:
                    quest_sol[question] = "No valid datagram lengths found in the alerts."
            elif i == 4:
                high_priority_count = 0
                for alert in snort_alerts:
                    priority = alert.get("priority")
                    if isinstance(priority, int) and priority == 1:
                        high_priority_count += 1
                quest_sol[question] = (
                    f"There are {high_priority_count} alerts with high priority (priority 1)."
                )
            elif i == 5:
                ip_classifications = {}
                for alert in snort_alerts:
                    src_ip = alert.get("source_ip", "")
                    classification = alert.get("classification", "Unknown")
                    ts = parse_timestamp(alert.get("timestamp", ""))
                    if src_ip and ts:
                        if src_ip not in ip_classifications:
                            ip_classifications[src_ip] = []
                        ip_classifications[src_ip].append((ts, classification))
                
                result = []
                for src_ip, entries in ip_classifications.items():
                    entries.sort(key=lambda x: x[0])  # Sort by timestamp
                    unique_classes = set()
                    window_start = entries[0][0]
                    for ts, cls in entries:
                        if ts <= window_start + 60:  # 1-minute window
                            unique_classes.add(cls)
                        else:
                            window_start = ts
                            unique_classes = {cls}
                        if len(unique_classes) > 1:
                            result.append(f"{src_ip} ({len(unique_classes)} classifications)")
                            break
                if result:
                    quest_sol[question] = f"Source IPs with multiple classifications in 1 minute: {', '.join(result)}."
                else:
                    quest_sol[question] = "No source IPs with multiple classifications found in 1 minute."
            elif i == 6:
                cve_pattern = re.compile(r'cve\.mitre\.org|cve-[0-9]{4}-[0-9]+', re.IGNORECASE)
                vulnerable_ports = {80, 443, 445}
                cve_alerts = []
                for alert in snort_alerts:
                    references = alert.get("references", [])
                    dest_port = alert.get("destination_port")
                    sid = alert.get("sid", "Unknown")
                    alert_id = alert.get("id", "Unknown")
                    message = alert.get("message", "Unknown")[:50]  # Limit message length
                    has_cve = any(cve_pattern.search(ref) for ref in references)
                    if has_cve and dest_port in vulnerable_ports:
                        cve_alerts.append(f"Alert SID {sid} (ID {alert_id}, port {dest_port}, message: {message})")
                if cve_alerts:
                    quest_sol[question] = (
                        f"{len(cve_alerts)} alerts with CVE references targeting vulnerable ports: {', '.join(cve_alerts)}."
                    )
                else:
                    quest_sol[question] = "No alerts with CVE references targeting ports 80, 443, or 445 found."
            elif i == 7:
                port_counts = {}
                for alert in snort_alerts:
                    dest_port = alert.get("destination_port")
                    if dest_port is not None:
                        port_counts[dest_port] = port_counts.get(dest_port, 0) + 1
                
                result = []
                if port_counts and num_alerts > 0:
                    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
                    for port, count in sorted_ports:
                        percentage = (count / num_alerts) * 100
                        result.append(f"{port} ({percentage:.2f}%, {count} alerts)")
                if result:
                    quest_sol[question] = f"Top destination ports: {', '.join(result)}."
                else:
                    quest_sol[question] = "No destination ports found in alerts."
            elif i == 8:
                ip_pairs_alerts = {}
                for alert in snort_alerts:
                    src_ip = alert.get("source_ip", "")
                    dest_ip = alert.get("destination_ip", "")
                    ts = parse_timestamp(alert.get("timestamp", ""))
                    if src_ip and dest_ip and ts:
                        key = (src_ip, dest_ip)
                        if key not in ip_pairs_alerts:
                            ip_pairs_alerts[key] = []
                        ip_pairs_alerts[key].append(ts)
                
                result = []
                for (src_ip, dest_ip), timestamps in ip_pairs_alerts.items():
                    timestamps.sort()
                    window_start = timestamps[0]
                    count = 1
                    for ts in timestamps[1:]:
                        if ts <= window_start + 30:  # 30-second window
                            count += 1
                        else:
                            window_start = ts
                            count = 1
                        if count >= 2:
                            result.append(f"{src_ip}: {count} alerts targeting {dest_ip} in {(ts - window_start):.2f}s")
                            break
                if result:
                    quest_sol[question] = f"Source IPs with focused attack attempts: {', '.join(result)}."
                else:
                    quest_sol[question] = "No source IPs with multiple alerts targeting the same destination in 30 seconds."

        return quest_sol

    def generate_dataset(self, name: str, context: list) -> None:
        """Generate a dataset in JSONL format from alert files."""
        dataset_dir = os.path.join(os.getcwd(), f"data/{name}/")
        os.makedirs(dataset_dir, exist_ok=True)

        for file_json in self.__files:
            print(f"Answering questions for {file_json}")
            try:
                question_and_answers = self.answer_questions_for_alerts(file_json)
                with open(os.path.join(self.__data_path, file_json), 'r') as alert_file:
                    alerts_data = json.load(alert_file)
                    alerts_str = json.dumps(alerts_data, indent=2, ensure_ascii=False)
                dataset_path = os.path.join(dataset_dir, f"{file_json.replace('.json', '')}_dataset.jsonl")
                with open(dataset_path, 'a') as f:
                    for idx, (question, answer) in enumerate(question_and_answers.items()):
                        # Default context for zero-shot
                        prompt_context = ""
                        if name == "one_shot" and idx < len(context):
                            # For one-shot, include the corresponding example
                            prompt_context = f"{context[idx]}\n\n"
                        elif name == "chain_of_thought" and idx < len(context):
                            # For chain-of-thought, include the corresponding example
                            prompt_context = f"{context[idx]}\n\n"
                        
                        # Construct the prompt with context (if any) and current alerts
                        prompt = f"{prompt_context}{alerts_str}\n\nQ: {question}"
                        data = {
                            #"context": "You are a cybersecurity analyst reviewing a complete list of Snort alerts formatted as JSON. Your task is to count and report the number of alert objects accurately. Keep your answers short, precise, and avoid extra explanations.",
                            "context": "You are an analyst answering questions  about a complete list of Snort alerts in JSON format. Be brief and accurate.",
                            "prompt": prompt,
                            "answer": answer
                        }
                        f.write(json.dumps(data) + "\n")
            except Exception as e:
                print(f"Error generating dataset for {file_json}. ERROR: {e}")
                import sys
                sys.exit(1)

    def __get_files(self, data_path: str) -> list:
        """Return a list of JSON files in the data path."""
        return [f for f in os.listdir(data_path) if f.endswith(".json")]

    def get_questions(self):
        """Return the list of questions."""
        return self.__questions