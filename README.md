# Phishing URL Detection System

## Introduction
Phishing attacks pose a significant threat to cybersecurity, necessitating robust detection mechanisms. In this study, we leverage a dataset of approximately 500,000 phishing URLs sourced from PhishTank to develop an efficient phishing detection system. 

We update labels of samples by verifying with VirusTotal. We begin by extracting 87 distinct features from the URLs and employ autoencoders for dimensionality reduction, condensing the feature space to 15 while preserving critical information. To classify phishing URLs, we train all four kernels of Support Vector Machines (SVM), achieving accuracy of **99.53%**.



## Demo

![image](https://github.com/user-attachments/assets/8743a26f-b5aa-47be-98dc-bbb3e5f6af89)

![image](https://github.com/user-attachments/assets/dd6beab1-3dea-41dd-b33e-4f70d8af6369)

![image](https://github.com/user-attachments/assets/31a923b0-87b5-4f83-867c-33e84e856112)

![image](https://github.com/user-attachments/assets/03246351-45ae-45bf-b78a-684c9723855b)

![image](https://github.com/user-attachments/assets/c438ca7b-6abc-4ef0-956a-c1b73cac49c9)


## Features
- **Next.js + TypeScript + FastAPI application** for phishing URL detection
- **Pickle-based model** for real-time predictions
- **Feature extraction and display** for each analyzed URL
- **PDF report generation** for detailed analysis
- **Bulk analysis support** via CSV file upload
- **Chrome Extension** for real-time phishing warnings during browsing

## Setup & Installation
### Frontend Setup
```bash
cd Application
cd frontend_nextjs
npm install
npm run dev
```

### Backend Setup
```bash
cd Application
cd backend
python -m venv env
source env/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

## Chrome Extension
We have developed a **Chrome Extension** to seamlessly integrate our phishing detection model into everyday browsing. When a user clicks on a suspected phishing URL, the extension triggers a warning popup, providing options to either proceed or go back. If the user chooses to continue, the website is logged and exempted from future checks, ensuring a balance between security and convenience. Load the Extension folder present inside Application to chrome extensions to use it.

![Screenshot from 2025-03-25 23-58-00](https://github.com/user-attachments/assets/bec69be4-c36b-4459-84b9-7b4ba2a6b226)

