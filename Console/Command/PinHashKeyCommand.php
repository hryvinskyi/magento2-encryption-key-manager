<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Console\Command;

use Hryvinskyi\EncryptionKeyManager\Api\HashKeyPinnerInterface;
use Magento\Framework\Console\Cli;
use Magento\Framework\Exception\LocalizedException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Pins keyed hashes to a key of the ring or to a kept key; translates the options and reports the fingerprint
 */
class PinHashKeyCommand extends Command
{
    private const NAME = 'encryption:hash-key:pin';
    private const OPTION_SLOT = 'slot';
    private const OPTION_INVALIDATED = 'invalidated';
    private const OPTION_REPLACE = 'replace';

    /**
     * @param HashKeyPinnerInterface $pinner pins the key
     */
    public function __construct(
        private readonly HashKeyPinnerInterface $pinner
    ) {
        parent::__construct();
    }

    /**
     * @inheritDoc
     */
    protected function configure(): void
    {
        $this->setName(self::NAME);
        $this->setDescription((string) __('Pin keyed hashes, such as product image cache paths, to one key'));
        $this->addOption(
            self::OPTION_SLOT,
            null,
            InputOption::VALUE_REQUIRED,
            (string) __(
                'The ring slot of the key to pin; the active key when neither this nor --%1 is given',
                self::OPTION_INVALIDATED
            )
        );
        $this->addOption(
            self::OPTION_INVALIDATED,
            null,
            InputOption::VALUE_REQUIRED,
            (string) __('The position, from 0, of a key kept in crypt/invalidated_key to pin instead of a ring key')
        );
        $this->addOption(
            self::OPTION_REPLACE,
            null,
            InputOption::VALUE_NONE,
            (string) __('Replace a key that is already pinned; every pinned hash changes')
        );
        $this->setHelp((string) __(
            'Copies the key to crypt/pinned_hash_key in app/etc/env.php. Run it before the first key is appended to '
            . 'the ring: without options it pins the active key, the one the store hashes with now. On a store whose '
            . 'old key was already taken out of the ring and kept in crypt/invalidated_key, pin that kept key with '
            . '--invalidated. Reload PHP-FPM afterwards if opcache does not revalidate app/etc/env.php.'
        ));
    }

    /**
     * @inheritDoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $slot = $this->position($input, self::OPTION_SLOT);
            $kept = $this->position($input, self::OPTION_INVALIDATED);
            $replace = (bool) $input->getOption(self::OPTION_REPLACE);
            if ($slot !== null && $kept !== null) {
                throw new LocalizedException(
                    __('Give --%1 or --%2, not both.', self::OPTION_SLOT, self::OPTION_INVALIDATED)
                );
            }
            $fingerprint = $kept === null
                ? $this->pinner->pinRingKey($slot, $replace)
                : $this->pinner->pinInvalidatedKey($kept, $replace);
        } catch (LocalizedException $exception) {
            $output->writeln('<error>' . $exception->getMessage() . '</error>');

            return Cli::RETURN_FAILURE;
        }
        $output->writeln('<info>' . __('Keyed hashes are pinned to key %1.', $fingerprint) . '</info>');

        return Cli::RETURN_SUCCESS;
    }

    /**
     * Read an option that names a slot or a position
     *
     * @param InputInterface $input the command input
     * @param string $name the option name
     * @return int|null the number, or null when the option is not given
     * @throws LocalizedException when the option is not a whole number from 0
     */
    private function position(InputInterface $input, string $name): ?int
    {
        $value = $input->getOption($name);
        if ($value === null) {
            return null;
        }
        if (!is_string($value) || !ctype_digit($value)) {
            throw new LocalizedException(__('--%1 is a whole number from 0.', $name));
        }

        return (int) $value;
    }
}
