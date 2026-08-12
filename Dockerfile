FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Back4App portu environment variable olarak verir
ENV PORT=10000
EXPOSE 10000

# Daha güvenli başlatma: hata detaylı görünür
CMD ["sh", "-c", "echo '=== Starting vavuubey-secure ===' && echo 'PORT='$PORT && python server.py 2>&1"]
