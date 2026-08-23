FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup --system detector && adduser --system --ingroup detector --no-create-home detector
COPY --chown=detector:detector detector.py /opt/lurebench/detector.py

USER detector
ENTRYPOINT ["python", "/opt/lurebench/detector.py"]
