import torch
from PIL import Image
from transformers import AutoImageProcessor, AutoModelForImageClassification

MODEL_NAME = "umm-maybe/AI-image-detector"

processor = AutoImageProcessor.from_pretrained(MODEL_NAME)
model = AutoModelForImageClassification.from_pretrained(MODEL_NAME)
model.eval()

img = Image.open("notaltered.jpeg").convert("RGB")
inputs = processor(images=img, return_tensors="pt")

with torch.no_grad():
    outputs = model(**inputs)

probs = torch.softmax(outputs.logits, dim=1)

print("Probabilities:", probs)
print("Labels:", model.config.id2label)
print("Prediction:", model.config.id2label[probs.argmax(dim=1).item()])