import json
import os
import re
import plotly.express as px
import plotly.graph_objects as go
import requests

class LLM_Evaluator:
    def __init__(
        self,
        model_to_eval: str = "llama2",
        evaluator_model: str = "llama3",
        dataset_path: str = "data/zero_shot/dataset.jsonl",
    ):
        self.__model_to_eval = model_to_eval
        self.__evaluator_model = evaluator_model
        self.__dataset = self.__load_dataset(dataset_path)

    def __load_dataset(self, dataset_path: str):
        dataset = []
        try:
            with open(os.path.join(os.getcwd(), dataset_path), "r") as f:
                for line in f:
                    dataset.append(json.loads(line))
        except Exception as error:
            print(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return dataset

    def answer_questions(
        self, output_path: str = "data/evaluation/generated_output.jsonl"
    ):
        os.makedirs("data/evaluation", exist_ok=True)
        with open(output_path, "a") as f:
            for data in self.__dataset:
                try:
                    output_text = ""
                    while not output_text:
                        output_text = self.__generate_response(
                            context=data["context"],
                            question=data["prompt"],
                            model=self.__model_to_eval,
                        )
                    f.write(
                        json.dumps(
                            {"prompt": data["prompt"], "generated_output": output_text}
                        )
                        + "\n"
                    )
                except Exception as error:
                    print(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            f.close()

    def evaluate_model(
        self, generated_output_path: str = "data/evaluation/generated_output.jsonl"
    ):
        generated_output = self.__load_dataset(generated_output_path)
        if not self.__dataset or not generated_output:
            print("Error: Dataset or generated output is empty.")
            return
        generated_output_path = generated_output_path.split("/")[-1].split(".")[0]
        with open(
            f"data/evaluation/evaluation_{generated_output_path}.jsonl", "a"
        ) as f:
            for i, generated_answer in enumerate(generated_output):
                try:
                    if i >= len(self.__dataset):
                        print(f"Error: Index {i} exceeds dataset size ({len(self.__dataset)}).")
                        continue
                    generated_answer = generated_answer["generated_output"]
                    real_answer = self.__dataset[i]["answer"]
                    context = r'You are a model used to evaluate if the answer of another model is correct. Compare the generated answer with the real answer. Mark it as correct ("is_correct": "Yes") if they convey the same meaning or provide the same information, even if the wording differs. Assign a punctuation from 0 to 100 based on accuracy and clarity (100 for exact or equivalent answers, lower for partial correctness). Answer ONLY in this JSON format: {"is_correct": "Yes" or "No", "punctuation": <Number from 0 to 100>}. Any other format will be considered wrong.'
                    input_text = f"Model to evaluate answer: {generated_answer}\nReal answer:\n{real_answer}"
                    output_text = ""
                    number_of_tries = 0
                    while not output_text:
                        output_text = self.__generate_response(
                            context=context,
                            question=input_text,
                            model=self.__evaluator_model,
                        )
                        if not re.match(
                            r'{"is_correct": "(Yes|No)", "punctuation": \d{1,3}}',
                            output_text,
                        ):
                            output_text = ""
                            print(
                                "Output text format is not like the expected, trying again."
                            )
                            number_of_tries += 1
                            if number_of_tries > 10:
                                print(
                                    "The model to evaluate the answer is not working properly, writing default answer and note and going to next question."
                                )
                                output_text = '{"is_correct": "No", "punctuation": 0, "note": "Model to evaluate the answer is not working properly"}'
                    final_output = json.loads(output_text)
                    f.write(
                        json.dumps(
                            {
                                "prompt": input_text,
                                "evaluation": final_output,
                            }
                        )
                        + "\n"
                    )
                except Exception as error:
                    print(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            f.close()

    def generate_report(self, evaluation_input: str):
        generated_output = self.__load_dataset(evaluation_input)
        data_per_question = {}
        for i in range(9):
            data_per_question[f"question{i}"] = {
                "correct": 0,
                "problematic_eval": 0,
                "total": 0,
                "total_punct": 0,
            }
        for i, generated_answer in enumerate(generated_output):
            try:
                evaluation = generated_answer["evaluation"]
                punctuation = evaluation["punctuation"]
                data_per_question[f"question{i % 9}"]["total"] += 1
                if evaluation["is_correct"] == "Yes":
                    data_per_question[f"question{i % 9}"]["correct"] += 1
                data_per_question[f"question{i % 9}"]["total_punct"] += punctuation
                if "note" in evaluation:
                    data_per_question[f"question{i % 9}"]["problematic_eval"] += 1
            except Exception as error:
                print(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        print("----------------")
        print("General report")
        print("----------------")
        total_correct = 0
        total_problematic_eval = 0
        total_questions = 0
        total_punct = 0
        for data in data_per_question.values():
            total_correct += data["correct"]
            total_problematic_eval = data["problematic_eval"]
            total_questions += data["total"]
            total_punct += data["total_punct"]
        print(f"Total correct answers: {total_correct}")
        print(f"Total problematic evaluations: {total_problematic_eval}")
        print(f"Total questions: {total_questions}")
        print(
            f"Average punctuation: {total_punct / total_questions if total_questions != 0 else 0}"
        )
        model_name = evaluation_input.split("/")[-1].split(".")[0].split("_")[-1]
        type_of_dataset = "_".join(
            evaluation_input.split("/")[-1].split(".")[0].split("_")[1:-1]
        )
        os.makedirs(
            f"data/evaluation/charts/{model_name}/{type_of_dataset}", exist_ok=True
        )
        fig = px.pie(
            values=[
                total_correct,
                total_questions - total_correct - total_problematic_eval,
                total_problematic_eval,
            ],
            names=["Correct", "Incorrect", "Problematic evaluations"],
            title=f"Correct and incorrect answers: {type_of_dataset.replace('_', ' ')} {model_name}",
        )
        fig.write_image(
            f"data/evaluation/charts/{model_name}/{type_of_dataset}/correct_incorrect_pie_chart.png"
        )
        print("----------------")
        print("Report by question")
        print("----------------")
        for i in range(9):
            try:
                correct = data_per_question[f"question{i}"]["correct"]
                total = data_per_question[f"question{i}"]["total"]
                total_punct = data_per_question[f"question{i}"]["total_punct"]
                problematic_eval = data_per_question[f"question{i}"]["problematic_eval"]
                print(
                    f"Question {i}: Correct: {correct}/{total} ({round(correct / total * 100, 2) if total != 0 else 0}%), Average punctuation: {round(total_punct / total, 2) if total != 0 else 0}, Problematic evaluations: {problematic_eval}"
                )
            except Exception as error:
                print(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        fig = go.Figure(
            data=[
                go.Bar(
                    name="Correct",
                    x=[f"Question {i + 1}" for i in range(9)],
                    y=[data["correct"] for data in data_per_question.values()],
                ),
                go.Bar(
                    name="Incorrect",
                    x=[f"Question {i + 1}" for i in range(9)],
                    y=[
                        data["total"] - data["correct"]
                        for data in data_per_question.values()
                    ],
                ),
            ]
        )
        fig.update_layout(
            barmode="group",
            title=f"Correct and incorrect answers by question: {type_of_dataset.replace('_', ' ')} {model_name}",
        )
        fig.write_image(
            f"data/evaluation/charts/{model_name}/{type_of_dataset}/correct_incorrect_bar_chart.png"
        )
        fig = go.Figure()
        fig.add_trace(
            go.Scatterpolar(
                r=[
                    (data["total_punct"] / data["total"])
                    for data in data_per_question.values()
                ],
                theta=[f"Question {i + 1}" for i in range(9)],
                fill="toself",
                name="Total punctuation",
            )
        )
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=False,
            title=f"Total punctuation by question: {type_of_dataset.replace('_', ' ')} {model_name}",
        )
        fig.write_image(
            f"data/evaluation/charts/{model_name}/{type_of_dataset}/total_punctuation_radar_chart.png"
        )

    def __generate_response(
        self,
        context: str,
        question: str,
        model: str,
        url: str = "http://localhost:11434/api/generate",
    ) -> str:
        response_text = ""
        if requests.get("http://localhost:11434").text != "Ollama is running":
            print("Ollama is not running, please start the Ollama API to continue.")
            input("Press any key to continue...")
        try:
            data = {
                "model": model,
                "system": context,
                "prompt": question,
                "stream": False,
                "options": {
                    "temperature": 0,
                },
            }
            response = requests.post(url, data=json.dumps(data))
            if response.status_code == 200:
                response_text = json.loads(response.text)["response"]
            else:
                print(f"Error: {response.status_code}")
        except Exception as error:
            print(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return response_text