FROM pwntools/pwntools:latest
ENV PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .

RUN sudo apt update && sudo apt install -y hashcash

RUN pip install --break-system-packages -r requirements.txt
