<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Plugin;

use Hryvinskyi\EncryptionKeyManager\Api\DecryptLogSettingsInterface;
use Hryvinskyi\EncryptionKeyManager\Api\DeploymentKeysInterface;
use Hryvinskyi\EncryptionKeyManager\Plugin\LogOldKeyDecrypts;
use Hryvinskyi\EncryptionKeyManager\Test\Unit\Fake\RecordingLogger;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Encryption\EncryptorInterface;
use Magento\Framework\Exception\RuntimeException;
use PHPUnit\Framework\TestCase;

/**
 * Logs decryptions under old keys, and only those, without the value or what it decrypts to
 */
class LogOldKeyDecryptsTest extends TestCase
{
    private const RING = [
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        'invalidAbCdEfGhIjKlMnOpQrStUvWxY',
        'f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5',
    ];
    private const OLD_VALUE = '0:3:c2VjcmV0LWNpcGhlcnRleHQtYnl0ZXMtaGVyZQ==';
    private const RETIRED_VALUE = '1:3:b3RoZXItY2lwaGVydGV4dC1ieXRlcy1oZXJl';
    private const ACTIVE_VALUE = '2:3:YWN0aXZlLWNpcGhlcnRleHQtYnl0ZXMtaGVyZQ==';

    /**
     * A decryption under an old key is logged with the indices and the stack, never the value or its plaintext
     *
     * @return void
     */
    public function testLogsADecryptionUnderAnOldKey(): void
    {
        $logger = new RecordingLogger();

        $result = $this->plugin(true, $logger)->afterDecrypt($this->subject(), 'plaintext', self::OLD_VALUE);

        self::assertSame('plaintext', $result);
        self::assertCount(1, $logger->records);
        $context = $logger->records[0]['context'];
        self::assertSame(0, $context['key_index']);
        self::assertSame(2, $context['active_index']);
        self::assertIsString($context['trace_id']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $context['trace_id']);
        self::assertIsString($context['trace']);
        self::assertStringContainsString(__FUNCTION__, $context['trace']);
        $logged = json_encode($logger->records, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString(self::OLD_VALUE, $logged);
        self::assertStringNotContainsString('plaintext', $logged);
        self::assertStringNotContainsString('/Volumes/', $context['trace']);
    }

    /**
     * A value under a retired slot is logged too: something still needs a key that is gone
     *
     * @return void
     */
    public function testLogsADecryptionUnderARetiredSlot(): void
    {
        $logger = new RecordingLogger();

        $result = $this->plugin(true, $logger)->afterDecrypt($this->subject(), '', self::RETIRED_VALUE);

        self::assertSame('', $result);
        self::assertSame(1, $logger->records[0]['context']['key_index'] ?? null);
    }

    /**
     * The same call site gets the same trace id
     *
     * @return void
     */
    public function testTheSameCallSiteGetsTheSameTraceId(): void
    {
        $logger = new RecordingLogger();
        $plugin = $this->plugin(true, $logger);

        for ($i = 0; $i < 2; $i++) {
            $plugin->afterDecrypt($this->subject(), 'x', self::OLD_VALUE);
        }

        self::assertSame($logger->records[0]['context']['trace_id'], $logger->records[1]['context']['trace_id']);
    }

    /**
     * Nothing is logged under the active key, for anything that is not a ciphertext, or while switched off
     *
     * @return void
     */
    public function testLogsNothingElse(): void
    {
        $logger = new RecordingLogger();
        $on = $this->plugin(true, $logger);
        $off = $this->plugin(false, $logger);

        self::assertSame('a', $on->afterDecrypt($this->subject(), 'a', self::ACTIVE_VALUE));
        self::assertSame('b', $on->afterDecrypt($this->subject(), 'b', 'plain text'));
        self::assertSame('c', $on->afterDecrypt($this->subject(), 'c', null));
        self::assertSame('d', $off->afterDecrypt($this->subject(), 'd', self::OLD_VALUE));

        self::assertSame([], $logger->records);
    }

    /**
     * The switch is not even read for a value under the active key
     *
     * @return void
     */
    public function testDoesNotReadTheSwitchUnderTheActiveKey(): void
    {
        $settings = $this->createMock(DecryptLogSettingsInterface::class);
        $settings->expects(self::never())->method('isEnabled');
        $plugin = new LogOldKeyDecrypts(
            $settings,
            $this->keys(),
            new DirectoryList(dirname(__DIR__, 3)),
            new RecordingLogger()
        );

        self::assertSame('a', $plugin->afterDecrypt($this->subject(), 'a', self::ACTIVE_VALUE));
        self::assertSame('b', $plugin->afterDecrypt($this->subject(), 'b', 'plain text'));
    }

    /**
     * A failing log or an unreadable configuration leaves the decryption's result as it was
     *
     * @return void
     */
    public function testAFailureToLogDoesNotChangeTheResult(): void
    {
        self::assertSame(
            'plaintext',
            $this->plugin(true, new RecordingLogger(true))->afterDecrypt($this->subject(), 'plaintext', self::OLD_VALUE)
        );

        $settings = $this->createMock(DecryptLogSettingsInterface::class);
        $settings->method('isEnabled')->willThrowException(new RuntimeException(__('unreadable')));
        $plugin = new LogOldKeyDecrypts(
            $settings,
            $this->keys(),
            new DirectoryList(dirname(__DIR__, 3)),
            new RecordingLogger()
        );

        self::assertSame('plaintext', $plugin->afterDecrypt($this->subject(), 'plaintext', self::OLD_VALUE));
    }

    /**
     * Build the plugin
     *
     * @param bool $enabled whether logging is switched on
     * @param RecordingLogger $logger the log
     * @return LogOldKeyDecrypts the plugin
     */
    private function plugin(bool $enabled, RecordingLogger $logger): LogOldKeyDecrypts
    {
        $settings = $this->createMock(DecryptLogSettingsInterface::class);
        $settings->method('isEnabled')->willReturn($enabled);

        return new LogOldKeyDecrypts($settings, $this->keys(), new DirectoryList(dirname(__DIR__, 3)), $logger);
    }

    /**
     * Deployment keys with a ring of three slots
     *
     * @return DeploymentKeysInterface the keys
     */
    private function keys(): DeploymentKeysInterface
    {
        $keys = $this->createMock(DeploymentKeysInterface::class);
        $keys->method('ring')->willReturn(self::RING);
        $keys->method('invalidated')->willReturn([]);

        return $keys;
    }

    /**
     * The encryptor the plugin observes
     *
     * @return EncryptorInterface the encryptor
     */
    private function subject(): EncryptorInterface
    {
        return $this->createMock(EncryptorInterface::class);
    }
}
