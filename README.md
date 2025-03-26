To run the application : \
cd Application \
cd frontend \
npm run dev \

cd Application \ 
cd backend \
python -m venv env \
pip install -r requirements.txt \
source env/bin/activate \
uvicorn api.main:app --reload \
