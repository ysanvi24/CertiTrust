# detector.py
import torch
from PIL import Image
from transformers import AutoImageProcessor, AutoModelForImageClassification

MODEL_NAME = "umm-maybe/AI-image-detector"

# Load once at startup (VERY IMPORTANT for performance)
processor = AutoImageProcessor.from_pretrained(MODEL_NAME)
model = AutoModelForImageClassification.from_pretrained(MODEL_NAME)
model.eval()

@torch.no_grad()
def analyze_image(image_path: str) -> dict:
    """
    Runs AI-based synthetic / manipulation detection
    """
    img = Image.open(image_path).convert("RGB")

    inputs = processor(images=img, return_tensors="pt")
    outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)[0]

    human = float(probs[0])
    artificial = float(probs[1])

    return {
        "ai_manipulation_likely": artificial > 0.2,
        "confidence": round(max(artificial, human), 4),
        "scores": {
            "artificial": round(artificial, 4),
            "human": round(human, 4),
        },
        "model": MODEL_NAME,
    }