<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Fake;

use Psr\Log\AbstractLogger;

/**
 * A logger that keeps every record it is given, or fails every write when told to
 */
class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{level: mixed, message: string, context: array<mixed>}>
     */
    public array $records = [];

    /**
     * @param bool $failing whether every write throws
     */
    public function __construct(
        private readonly bool $failing = false
    ) {
    }

    /**
     * Keep the record, or fail
     *
     * @param mixed $level the level
     * @param string|\Stringable $message the message
     * @param array<mixed> $context the context
     * @return void
     * @throws \RuntimeException when the logger is failing
     */
    public function log($level, string|\Stringable $message, array $context = []): void
    {
        if ($this->failing) {
            throw new \RuntimeException('The log cannot be written.');
        }
        $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }
}
