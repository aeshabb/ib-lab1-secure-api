FROM python:3.11-slim
WORKDIR /app
COPY requirements-fixed.txt /app/
RUN pip install --no-cache-dir -r requirements-fixed.txt
COPY app.py /app/
COPY static /app/static
COPY private /app/private
ENV HOST=0.0.0.0 PORT=8080 FOLLOW_SYMLINKS=false
CMD ["python", "app.py"]
