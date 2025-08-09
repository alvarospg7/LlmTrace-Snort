import os
import json
import shutil
import random

# Estimación conservadora: 75 tokens por alerta
TOKENS_PER_ALERT_ESTIMATE = 75

# Ventanas de contexto por modelo (dejando 1000 tokens de margen para prompt)
MODEL_TOKEN_LIMITS = {
    "llama3": 8192 - 1000,
    "mistral": 8192 - 1000,
    "phi4": 128000 - 1000,
    "deepseek-r1": 32768 - 1000,
    "qwen2.5-coder": 32768 - 1000  #Tiende a sobrehablar
}


# Límite mínimo entre todos los modelos
MIN_TOKEN_LIMIT = min(MODEL_TOKEN_LIMITS.values())
MAX_ALERTS = MIN_TOKEN_LIMIT // TOKENS_PER_ALERT_ESTIMATE  # ≈ 41 alertas por archivo

# Nuevo límite forzado para los bloques
MIN_ALERTS_PER_CHUNK = 6
MAX_ALERTS_PER_CHUNK = 15

RAW_DATA_PATH = os.path.join(os.getcwd(), "data/raw")
CLEANED_DATA_PATH = os.path.join(os.getcwd(), "data/cleaned")

def split_and_clean_alerts_random(input_file: str, max_chunks: int = 10) -> None:
    """Divide un archivo grande en bloques aleatorios entre 6 y 15 alertas y los guarda."""
    with open(input_file, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print(f"[!] {input_file} no contiene una lista JSON.")
        return

    total_alerts = len(data)
    base_filename = os.path.splitext(os.path.basename(input_file))[0]
    used_indices = set()

    for i in range(max_chunks):
        num_alerts = random.randint(MIN_ALERTS_PER_CHUNK, min(MAX_ALERTS_PER_CHUNK, MAX_ALERTS))

        if total_alerts <= num_alerts:
            start_index = 0
        else:
            start_index = random.randint(0, total_alerts - num_alerts)

        # Evitar bloques idénticos
        while start_index in used_indices:
            start_index = random.randint(0, total_alerts - num_alerts)
        used_indices.add(start_index)

        chunk = data[start_index:start_index + num_alerts]
        output_file = os.path.join(CLEANED_DATA_PATH, f"{base_filename}_randpart{i+1}.json")
        with open(output_file, "w") as out_f:
            json.dump(chunk, out_f, indent=2)
        print(f"[+] Guardado bloque aleatorio: {output_file} ({len(chunk)} alertas, pos {start_index}-{start_index + len(chunk)})")

def clean_raw_data():
    os.makedirs(CLEANED_DATA_PATH, exist_ok=True)

    for file in sorted(os.listdir(RAW_DATA_PATH))[:10]:
        if not file.endswith(".json"):
            print(f"[-] Ignorado: {file} (no es JSON)")
            continue

        full_path = os.path.join(RAW_DATA_PATH, file)
        try:
            with open(full_path, "r") as f:
                data = json.load(f)

            if not isinstance(data, list):
                print(f"[!] {file} no contiene una lista JSON.")
                continue

            num_alerts = len(data)

            if num_alerts == 0:
                print(f"[!] {file} está vacío.")
                continue
            elif num_alerts <= MAX_ALERTS:
                dest_path = os.path.join(CLEANED_DATA_PATH, file)
                shutil.copyfile(full_path, dest_path)
                print(f"[✓] Copiado sin dividir: {file} ({num_alerts} alertas)")
            else:
                print(f"[⤵] Dividiendo aleatoriamente {file} ({num_alerts} alertas)...")
                split_and_clean_alerts_random(full_path, max_chunks=10)

        except Exception as e:
            print(f"[X] Error procesando {file}: {e}")

if __name__ == "__main__":
    clean_raw_data()
