<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Fake;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\DeploymentConfig\Reader;
use Magento\Framework\App\DeploymentConfig\Writer;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Config\File\ConfigFilePool;
use Magento\Framework\Filesystem;
use Magento\Framework\Filesystem\Directory\ReadFactory;
use Magento\Framework\Filesystem\Directory\WriteFactory;
use Magento\Framework\Filesystem\DriverPool;

/**
 * A store root in a temporary directory with real app/etc/env.php and app/etc/config.php files, and the store's own
 * reader and writer of its deployment configuration over them
 */
class DeploymentConfigFiles
{
    /**
     * @var string the temporary store root
     */
    private readonly string $root;

    /**
     * @var DeploymentConfig the store's deployment configuration over the files
     */
    private readonly DeploymentConfig $deploymentConfig;

    /**
     * @var Writer the store's writer of the files
     */
    private readonly Writer $writer;

    /**
     * @param array<string, mixed> $env what app/etc/env.php returns
     */
    public function __construct(array $env)
    {
        $this->root = sys_get_temp_dir() . '/ekm-' . bin2hex(random_bytes(6));
        mkdir($this->root . '/app/etc', 0700, true);
        $config = "<?php\nreturn " . var_export(['modules' => []], true) . ";\n";
        file_put_contents($this->root . '/app/etc/config.php', $config);
        file_put_contents($this->envPath(), "<?php\nreturn " . var_export($env, true) . ";\n");

        $directoryList = new DirectoryList($this->root);
        $driverPool = new DriverPool();
        $configFilePool = new ConfigFilePool();
        $reader = new Reader($directoryList, $driverPool, $configFilePool);
        $this->deploymentConfig = new DeploymentConfig($reader);
        $filesystem = new Filesystem($directoryList, new ReadFactory($driverPool), new WriteFactory($driverPool));
        $this->writer = new Writer($reader, $filesystem, $configFilePool, $this->deploymentConfig);
    }

    /**
     * The store's deployment configuration over the files
     *
     * @return DeploymentConfig the configuration
     */
    public function deploymentConfig(): DeploymentConfig
    {
        return $this->deploymentConfig;
    }

    /**
     * The store's writer of the files
     *
     * @return Writer the writer
     */
    public function writer(): Writer
    {
        return $this->writer;
    }

    /**
     * What app/etc/env.php returns now, read fresh from the file
     *
     * @return array<mixed> the configuration
     */
    public function env(): array
    {
        $env = include $this->envPath();

        return is_array($env) ? $env : [];
    }

    /**
     * Path of app/etc/env.php
     *
     * @return string the path
     */
    public function envPath(): string
    {
        return $this->root . '/app/etc/env.php';
    }

    /**
     * Remove the temporary store root
     *
     * @return void
     */
    public function remove(): void
    {
        foreach (['/app/etc/env.php', '/app/etc/config.php'] as $file) {
            if (is_file($this->root . $file)) {
                chmod($this->root . $file, 0600);
                unlink($this->root . $file);
            }
        }
        rmdir($this->root . '/app/etc');
        rmdir($this->root . '/app');
        rmdir($this->root);
    }
}
