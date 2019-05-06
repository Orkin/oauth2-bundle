<?php

namespace Trikoder\Bundle\OAuth2Bundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Trikoder\Bundle\OAuth2Bundle\Manager\ClientFilter;
use Trikoder\Bundle\OAuth2Bundle\Manager\ClientManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\Client;

final class ListClientsCommand extends Command
{
    public const ALLOWED_COLUMNS = ['identifier', 'secret', 'scope', 'redirect uri', 'grant type'];

    protected static $defaultName = 'trikoder:oauth2:list-clients';
    private $clientManager;

    public function __construct(ClientManagerInterface $clientManager)
    {
        parent::__construct();
        $this->clientManager = $clientManager;
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Lists existing oAuth2 clients')
            ->addOption(
                'columns',
                null,
                InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
                'Determine which columns are shown. Comma separated list.',
                self::ALLOWED_COLUMNS
            )
            ->addOption(
                'redirect-uri',
                null,
                InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
                'Finds by redirect uri for client. Use this option multiple times to filter by multiple redirect URIs.',
                []
            )
            ->addOption(
                'grant-type',
                null,
                InputOption::VALUE_IS_ARRAY | InputOption::VALUE_REQUIRED,
                'Finds by allowed grant type for client. Use this option multiple times to filter by multiple grant types.',
                []
            )
            ->addOption(
                'scope',
                null,
                InputOption::VALUE_IS_ARRAY | InputOption::VALUE_OPTIONAL,
                'Finds by allowed scope for client. Use this option multiple times to find by multiple scopes.',
                []
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $criteria = $this->getFindByCriteria($input);
        $clients = $this->clientManager->list($criteria);
        $this->drawTable($input, $output, $clients);

        return 0;
    }

    private function getFindByCriteria(InputInterface $input): ClientFilter
    {
        return
            ClientFilter
                ::create()
                ->addGrantCriteria($input->getOption('grant-type'))
                ->addRedirectUriCriteria($input->getOption('redirect-uri'))
                ->addScopeCriteria($input->getOption('scope'))
            ;
    }

    private function drawTable(InputInterface $input, OutputInterface $output, array $clients): void
    {
        $io = new SymfonyStyle($input, $output);
        $columns = $this->getColumns($input);
        $rows = $this->getRows($clients, $columns);
        $io->table($columns, $rows);
    }

    private function getRows(array $clients, array $columns): array
    {
        return array_map(function (Client $client) use ($columns) {
            $values = [
                'identifier' => $client->getIdentifier(),
                'secret' => $client->getSecret(),
                'scope' => implode(', ', $client->getScopes()),
                'redirect uri' => implode(', ', $client->getRedirectUris()),
                'grant type' => implode(', ', $client->getGrants()),
            ];

            return array_map(function ($column) use ($values) {
                return $values[$column];
            }, $columns);
        }, $clients);
    }

    private function getColumns(InputInterface $input): array
    {
        $allowedColumns = self::ALLOWED_COLUMNS;

        $requestedColumns = $input->getOption('columns');
        $requestedColumns = array_map(function ($column) {
            return strtolower(trim($column));
        }, $requestedColumns);

        return array_intersect($requestedColumns, $allowedColumns);
    }
}
