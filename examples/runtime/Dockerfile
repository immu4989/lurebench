FROM python:3.12-slim

RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY lurebench ./lurebench
COPY spec ./spec
RUN python -m pip install --no-cache-dir .

USER 65532:65532
EXPOSE 8765
ENTRYPOINT ["lurebench", "permit-serve"]
CMD ["--host", "127.0.0.1", "--port", "8765"]
