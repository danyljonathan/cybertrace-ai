FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8001 \
    CYBERTRACE_DATA_DIR=/app/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY run.py .

RUN useradd --create-home appuser && mkdir -p /app/data && chown -R appuser /app
USER appuser

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8001\")}/api/health')"
CMD ["python", "run.py"]
