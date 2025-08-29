import json
import glob
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Lista de modelos y técnicas conocidas
models_known = ["llama3", "phi4", "mistral", "qwen2_5"]
techniques_known = ["zero_shot", "one_shot", "chain_of_thought", "few_shot"]

eval_path = "./"
data_list = []

# Leer todos los ficheros
for file in glob.glob(os.path.join(eval_path, "evaluation_*_combined.jsonl")):
    basename = os.path.basename(file)
    core = basename.replace("evaluation_", "").replace("_combined.jsonl", "")
    
    # Detectar modelo
    model = None
    for m in models_known:
        if core.startswith(m):
            model = m
            break
    if model is None:
        continue

    # Detectar técnica
    technique = None
    for t in techniques_known:
        if t in core:
            technique = t
            break
    if technique is None:
        continue

    # Contar respuestas correctas
    with open(file, "r") as f:
        correct = 0
        total = 0
        for line in f:
            item = json.loads(line)
            eval_info = item.get("evaluation", {})
            if eval_info.get("is_correct") == "Yes":
                correct += 1
            total += 1
        
        # Solo agregar si hay datos
        if total > 0:
            f1 = correct / total
            data_list.append({"Modelo": model, "Técnica": technique, "F1": f1})

# Crear DataFrame
df = pd.DataFrame(data_list)

# Filtrar filas sin datos o F1 = 0
df_plot = df[df['F1'].notna() & (df['F1'] > 0)]

# --- Gráfico ---
sns.set_theme(style="whitegrid", font_scale=1.5)
plt.figure(figsize=(12,8))

palette = sns.color_palette("Set2", n_colors=len(techniques_known))

# Orden fijo
model_order = ["llama3", "phi4", "mistral", "qwen2_5"]
technique_order = ["zero_shot", "one_shot", "chain_of_thought", "few_shot"]

bar_plot = sns.barplot(
    x="Modelo",
    y="F1",
    hue="Técnica",
    data=df_plot,
    palette=palette,
    order=model_order,
    hue_order=technique_order
)

# Etiquetas encima de las barras
for p in bar_plot.patches:
    height = p.get_height()
    if not pd.isna(height):
        bar_plot.annotate(f"{height:.2f}",
                          (p.get_x() + p.get_width() / 2., height),
                          ha="center", va="bottom", fontsize=12, fontweight="bold", color="black", rotation=90)

# Ejes y título
plt.ylim(0, 1.0)
plt.title("Rendimiento de los modelos por técnica de prompting", fontsize=20, fontweight="bold", pad=20)
plt.ylabel("F1 score", fontsize=18, fontweight="bold")
plt.xlabel("Modelo", fontsize=18, fontweight="bold")

# Ajuste de leyenda
plt.legend(title="Técnica", fontsize=14, title_fontsize=14)

# Negrita y tamaño de ticks
bar_plot.set_xticklabels(bar_plot.get_xticklabels(), fontweight="bold", fontsize=16)
bar_plot.tick_params(axis='y', labelsize=16)

plt.tight_layout()
plt.savefig("rendimiento_modelos_por_tecnica.png", dpi=300)
plt.savefig("rendimiento_modelos_por_tecnica.pdf")
plt.show()
