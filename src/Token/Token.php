<?php

/**
 * Copyright (c) 2010-2016 Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eureka\Component\Token;

use \Eureka\Component\Mcrypt\Mcrypt;

/**
 * Class to manage token for API
 *
 * @author  Romain Cottard
 */
class Token
{
    /**
     * @var integer $authId Authentication ID (provider id, user id...)
     */
    private $authId = '';

    /**
     * @var string $keySalt Salt key for encryption. Must be defined by server API.
     */
    private $keySalt = '';

    /**
     * @var integer Expiration time in second (timestamp).
     */
    private $expirationTime = 0;

    /**
     * @var integer Expiration delay in second.
     */
    private $expirationDelay = 0;

    /**
     * Return authentication ID
     *
     * @return int
     */
    public function getAuthId()
    {
        return $this->authId;
    }

    /**
     * Set Auth ID.
     *
     * @param  integer $authId
     * @return self
     * @throws \UnderflowException
     */
    public function setAuthId($authId)
    {
        $this->authId = (int) $authId;

        if ($this->authId <= 0) {
            throw new \UnderflowException('Auth ID must be greater than 0 !', 16001);
        }

        return $this;
    }

    /**
     * Set expiration delay in second.
     *
     * @param  int $seconds
     * @return self
     * @throws \UnderflowException
     */
    public function setExpirationDelay($seconds)
    {
        $this->expirationDelay = (int) $seconds;

        if ($this->expirationDelay <= 0) {
            throw new \UnderflowException('Expiration delay must be greater than 0 !', 16002);
        }

        $this->expirationTime = time() + $this->expirationDelay;

        return $this;
    }

    /**
     * Return expiration time
     *
     * @return int
     */
    public function getExpirationTime()
    {
        return $this->expirationTime;
    }

    /**
     * Set expiration time
     *
     * @param  integer
     * @return self
     * @throws \UnderflowException
     */
    protected function setExpirationTime($time)
    {
        $this->expirationTime = (int) $time;

        if ($this->expirationTime <= 0) {
            throw new \UnderflowException('Expiration time must be greater than 0 !', 16003);
        }
    }

    /**
     * Set Salt key
     *
     * @param  string $key
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setKeySalt($key)
    {
        $this->keySalt = (string) $key;

        if (empty($this->keySalt)) {
            throw new \InvalidArgumentException('Secret key cannot be empty !', 16004);
        }

        return $this;
    }

    /**
     * Check if token is expired
     *
     * @return bool
     */
    public function isExpired()
    {
        return ($this->expirationTime < time());
    }

    /**
     * Encrypt data and return token.
     *
     * @return string
     * @throws \LogicException
     */
    public function encrypt()
    {
        if (empty($this->keySalt)) {
            throw new \LogicException('The salt key must be defined before to encrypting the token !', 16005);
        }

        $mcrypt = new Mcrypt();
        $mcrypt->setKey($this->keySalt);

        $data  = $this->getDataPacked(); // Get packed data
        $token = $mcrypt->encrypt($data . $this->getCRC32Packed($data)); // Encrypt data
        $token = base64_encode($mcrypt->getIV() . $token); // add IV & encode into base64

        return $token;
    }

    /**
     * Decrypt token.
     *
     * @param  string $token
     * @return self
     * @throws \RuntimeException
     */
    public function decrypt($token)
    {
        if (empty($this->keySalt)) {
            throw new \RuntimeException('The salt key must be defined before to encrypting the token !');
        }

        $mcrypt = new Mcrypt();
        $mcrypt->setKey($this->keySalt);

        $token = base64_decode($token); // Decode
        $iv    = substr($token, 0, $mcrypt->getSizeIV()); // Get IV string
        $token = substr($token, $mcrypt->getSizeIV()); // Get encrypted token
        $data  = $mcrypt->setIV($iv)
            ->decrypt($token); // Decrypt data

        $unpackedData = unpack('H12rand/VauthId/VexpirationTime/Vcrc32', $data);

        if ($unpackedData === false) {
            throw new \RuntimeException('Cannot unpack token data !');
        }

        $this->setAuthId($unpackedData['authId']);
        $this->setExpirationTime($unpackedData['expirationTime']);

        if (!$this->checkCRC32($unpackedData['crc32'], $unpackedData['rand'])) {
            throw new \RuntimeException('CRC value of the token not corresponding to the expected value !', 16007);
        }

        return $this;
    }

    /**
     * Check CRC32 of the packed data.
     *
     * @param  integer $rand
     * @param  string  $crc32
     * @return bool
     */
    protected function checkCRC32($crc32, $rand)
    {
        return ($crc32 === crc32($this->getDataPacked($rand, false)));
    }

    /**
     * Get packed data to encrypt
     *
     * @param  int  $rand
     * @param  bool $checkTime
     * @return string
     * @throws \LogicException
     * @throws \UnderflowException
     */
    protected function getDataPacked($rand = null, $checkTime = true)
    {
        if ($this->authId < 0) {
            throw new \LogicException('Auth ID must be defined to create the token!', 16008);
        }

        if ($checkTime && $this->getExpirationTime() < time()) {
            throw new \UnderflowException('Expired token!', 16009);
        }

        if ($rand === null) {
            //~ Auth ID: 4bytes, expiration time: 4bytes, crc32: 4bytes
            //~ So, use 12bytes for rand data to have 3 blocks of 8bytes
            $rand = bin2hex(openssl_random_pseudo_bytes(12));
        }

        return pack('H12VV', $rand, (int) $this->getAuthId(), $this->getExpirationTime());
    }

    /**
     * Get crc32 for packed data
     *
     * @param  string $data
     * @return string
     */
    protected function getCRC32Packed($data)
    {
        return pack('V', crc32($data));
    }
}
