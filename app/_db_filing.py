import asyncio

from db.base import get_session
from db.models import Service


async def main(test_password: str) -> None:
    async with get_session() as session:
        session.add(
            Service(
                login="books",
                role="MEDIA_ACCESS",
            ).set_password(test_password)
        )
        session.add(
            Service(
                login="internal_media",
                role="MINMUM",
            ).set_password(test_password)
        )
        session.add(
            Service(
                login="users",
                role="SERVES_USERS",
            ).set_password(test_password)
        )
        session.add(
            Service(
                login="_test",
                role="_TEST",
            ).set_password(test_password)
        )
        session.add(
            Service(
                login="forum",
                role="MEDIA_ACCESS",
            ).set_password(test_password)
        )
        session.add(
            Service(
                login="api_gateway",
                role="PROXY",
            ).set_password(test_password)
        )
        await session.commit()

if __name__ == "__main__":
    _test_password = "qwe"
    from db.base import _db_init
    from db.models import *  # noqa: F401, F403

    _db_init()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(_test_password))
