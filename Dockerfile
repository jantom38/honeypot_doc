FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 2222 8080 2121 2323 2525 3306 8501

CMD ["python", "main.py"]
