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
        print(prediction)
        return {"prediction": prediction,"URL_Length":0,"having_At_Symbol":0,"double_slash_redirecting":0,"Prefix_Suffix":0,"having_Sub_Domain":0,"SSLfinal_State":0,"Domain_registeration_length":0,"Favicon":0,"port":0,"HTTPS_token":0,"Request_URL":0,"URL_of_Anchor":0,"Links_in_tags":0,"SFH":0,"Submitting_to_email":0,"Abnormal_URL":0,"Redirect":0,"on_mouseover":0,"RightClick":0,"popUpWidnow":0,"Iframe":0,"age_of_domain":0,"DNSRecord":0,"web_traffic":0,"Page_Rank":0,"Google_Index":0,"Links_pointing_to_page":0,"Statistical_report":0}
        

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
