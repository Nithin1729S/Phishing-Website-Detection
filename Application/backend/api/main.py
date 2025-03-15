import pickle
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Define request model
class URLRequest(BaseModel):
    url: str  

# Initialize FastAPI app
app = FastAPI()

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the pre-trained phishing detection model
model_path = "model/phishing.pkl"
try:
    with open(model_path, "rb") as model_file:
        loaded_model = pickle.load(model_file)
except Exception as e:
    raise RuntimeError(f"Failed to load the model: {e}")

@app.get("/")
def health_check():
    return {"status": "OK"}

@app.post("/api/check-phishing")
async def check_phishing(request: URLRequest):
    try:
        url = request.url
        prediction = loaded_model.predict([url])[0]  # Get prediction
        return {"url": url, "prediction": prediction}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
