import time
from fastapi import Request
from utils.logger import logger

async def log_requests(request: Request, call_next):
    start_time = time.time()

    logger.info(f"Incoming Request - Method: {request.method} - Path: {request.url.path}")

    response = await call_next(request)

    process_time = time.time() - start_time

    logger.info(f"Completed - Status: {response.status_code} - Time: {process_time:.4f} seconds")

    return response