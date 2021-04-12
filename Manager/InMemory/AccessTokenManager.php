<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Manager\InMemory;

use Carbon\CarbonImmutable;
use Trikoder\Bundle\OAuth2Bundle\Manager\AccessTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\AccessTokenInterface;

final class AccessTokenManager implements AccessTokenManagerInterface
{
    /**
     * @var AccessTokenInterface[]
     */
    private $accessTokens = [];

    /** @var bool */
    private $disableAccessTokenSaving;

    public function __construct(bool $disableAccessTokenSaving)
    {
        $this->disableAccessTokenSaving = $disableAccessTokenSaving;
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $identifier): ?AccessTokenInterface
    {
        if ($this->disableAccessTokenSaving) {
            return null;
        }

        return $this->accessTokens[$identifier] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function save(AccessTokenInterface $accessToken): void
    {
        if ($this->disableAccessTokenSaving) {
            return;
        }

        $this->accessTokens[$accessToken->getIdentifier()] = $accessToken;
    }

    public function clearExpired(): int
    {
        if ($this->disableAccessTokenSaving) {
            return 0;
        }

        $count = \count($this->accessTokens);

        $now = CarbonImmutable::now();
        $this->accessTokens = array_filter($this->accessTokens, static function (AccessTokenInterface $accessToken) use ($now): bool {
            return $accessToken->getExpiry() >= $now;
        });

        return $count - \count($this->accessTokens);
    }

    public function clearRevoked(): int
    {
        $count = \count($this->accessTokens);

        $this->accessTokens = array_filter($this->accessTokens, static function (AccessTokenInterface $accessToken): bool {
            return !$accessToken->isRevoked();
        });

        return $count - \count($this->accessTokens);
    }
}
