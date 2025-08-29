import json
import glob
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Lista de modelos a considerar
models_known = ["llama3", "phi4", "mistral", "qwen2_5"]

eval_path = "./"
data_list = []

# Leer todos los ficheros de evaluación
for file in glob.glob(os.path.join(eval_path, "evaluation_*_combined.jsonl")):
    basename = os.path.basename(file)
    core = basename.replace("evaluation_", "").replace("_combined.jsonl", "")
    
    model = None
    for m in models_known:
        if core.startswith(m):
            model = m
            break
    if model is None:
        continue

    with open(file, "r") as f:
        correct = 0
        total = 0
        for line in f:
            item = json.loads(line)
            eval_info = item.get("evaluation", {})
            if eval_info.get("is_correct") == "Yes":
                correct += 1
            total += 1
        f1 = correct / total if total > 0 else 0

    data_list.append({"Modelo": model, "F1": f1})

df = pd.DataFrame(data_list)
df_grouped = df.groupby("Modelo", as_index=False).mean()
df_grouped = df_grouped.sort_values("F1", ascending=False)

# --- Estilo gráfico ---
sns.set_theme(style="whitegrid", font_scale=1.5)  # mayor escala de fuente
plt.figure(figsize=(10,7))  # más grande

palette = sns.color_palette("Set2", n_colors=len(df_grouped))

bar_plot = sns.barplot(
    x="Modelo",
    y="F1",
    data=df_grouped,
    palette=palette
)

# Etiquetas encima de las barras
for p in bar_plot.patches:
    height = p.get_height()
    bar_plot.annotate(f"{height:.2f}",
                      (p.get_x() + p.get_width() / 2., height),
                      ha="center", va="bottom", fontsize=16, fontweight="bold", color="black")

# Ejes y título
plt.ylim(0, 1.0)
plt.title("Rendimiento medio de los modelos (F1 score)", fontsize=20, fontweight="bold", pad=20)
plt.ylabel("F1 score", fontsize=18, fontweight="bold")
plt.xlabel("Modelo", fontsize=18, fontweight="bold")

# Negrita y tamaño de ticks
bar_plot.set_xticklabels(bar_plot.get_xticklabels(), fontweight="bold", fontsize=16)
bar_plot.tick_params(axis='y', labelsize=16)

plt.tight_layout()
plt.savefig("rendimiento_modelos_general.png", dpi=300)
plt.savefig("rendimiento_modelos_general.pdf")
plt.show()
