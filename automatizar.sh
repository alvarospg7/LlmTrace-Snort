#!/bin/bash

mkdir -p data/answers
mkdir -p data/evaluation
mkdir -p data/reports

models_to_evaluate=("phi4 mistral llama3 qwen2.5-coder llama2")
prompting_techniques=("zero_shot" "one_shot" "chain_of_thought")

for model in "${models_to_evaluate[@]}"; do
  # quitar sufijo -coder y reemplazar caracteres problemáticos
  
  model_base=$model
  #model_base=${model%-coder}
  model_base=${model_base//./_}
  model_base=${model_base//:/_}  # 🔧 Reemplaza ":" por "_"

  for prompt_tech in "${prompting_techniques[@]}"; do
    for dataset_file in data/${prompt_tech}/*_dataset.jsonl; do
      filename=$(basename "$dataset_file" _dataset.jsonl)

      output_path="data/answers/${model_base}_${prompt_tech}_${filename}_answers.jsonl"
      eval_path="data/evaluation/evaluation_${model_base}_${prompt_tech}_${filename}_answers.jsonl"
      report_path="data/reports/${model_base}_${prompt_tech}_${filename}_report.json"

      echo "==============================="
      echo "📤 Ejecutando preguntas:"
      echo "Modelo: $model"
      echo "Dataset: $dataset_file"
      echo "==============================="

      python src/wireshairk/__main__.py answer-questions \
        --model "$model" \
        --dataset_path "$dataset_file" \
        --output_path "$output_path"

      if [[ -f "$output_path" ]]; then
        echo "✅ Respuestas generadas en: $output_path"

        echo "🧪 Evaluando respuestas..."
        python src/wireshairk/__main__.py evaluate \
          --dataset_path "$dataset_file" \
          --generated_output "$output_path"

        if [[ -f "$eval_path" ]]; then
          echo "📊 Generando informe..."
          python src/wireshairk/__main__.py generate-report \
            --evaluation_input "$eval_path"
          echo "✅ Informe generado en: $report_path"
        else
          echo "❌ ERROR: No se encontró el archivo de evaluación: $eval_path"
        fi
      else
        echo "❌ ERROR: No se generó el archivo de respuestas: $output_path"
      fi
      echo ""
    done
  done
done
