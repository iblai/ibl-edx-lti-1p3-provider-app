from pylti1p3.contrib.django.session import DjangoSessionService


class FakeDjangoSessionService(DjangoSessionService):
    def check_nonce(self, nonce: str) -> bool:
        return True

    def check_state_is_valid(self, state: str, id_token_hash: str) -> bool:
        return True
