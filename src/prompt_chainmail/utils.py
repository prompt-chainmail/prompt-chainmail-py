STRING_CHUNKING_THRESHOLD = 64 * 1024
MAX_CHUNK_SIZE = 4096
MAX_INPUT_SIZE = 2 * 1024 * 1024


def to_chunks(input: str, chunk_size: int) -> list[str]:
    if chunk_size == 0 or not input:
        return [input]

    chunks: list[str] = []
    start = 0
    count = 0
    for idx, _ch in enumerate(input):
        if count == chunk_size:
            chunks.append(input[start:idx])
            start = idx
            count = 0
        count += 1
    chunks.append(input[start:])
    return chunks
