from uuid import uuid4


def gen_uuid(string):
    return f'{string}--{uuid4()}'

