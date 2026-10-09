FROM python:3.12.15-slim
WORKDIR /app
COPY agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home kyc
COPY agent /app/agent
COPY backend/src/main/resources/config/security_policy.json /app/config/security_policy.json
ENV FUSE_SECURITY_POLICY_PATH=/app/config/security_policy.json
USER 10001
EXPOSE 8001
CMD ["uvicorn", "agent.app:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log", "--limit-concurrency", "32", "--timeout-keep-alive", "5"]
