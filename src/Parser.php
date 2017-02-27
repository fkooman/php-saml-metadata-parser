<?php

/**
 * Copyright 2017 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace fkooman\SAML\Metadata;

use SimpleXMLElement;

class Parser
{
    /** @var \SimpleXMLElement */
    private $metadata;

    public function __construct($metadataFile)
    {
        if (false === $metadata = @simplexml_load_file($metadataFile)) {
            throw new ParserException(sprintf('unable to read file "%s"', $metadataFile));
        }
        $metadata->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $this->metadata = $metadata;
    }

    public function getIdps()
    {
        $idpList = [];

        $entityList = $this->metadata->xpath('//md:EntityDescriptor');
        foreach ($entityList as $entity) {
            $entityId = (string) $entity['entityID'];
            $idpDescriptor = $entity->xpath('md:IDPSSODescriptor');
            if (0 !== count($idpDescriptor)) {
                // we have an IdP
                $idpList[] = [
                    'entityId' => $entityId,
                    'SingleSignOnService' => $this->getSso($idpDescriptor[0]),
                    'keys' => $this->getKeys($idpDescriptor[0]),
                ];
            }
        }

        return $idpList;
    }

    public function getSps()
    {
        $spList = [];

        $entityList = $this->metadata->xpath('//md:EntityDescriptor');
        foreach ($entityList as $entity) {
            $entityId = (string) $entity['entityID'];
            $spDescriptor = $entity->xpath('md:SPSSODescriptor');
            if (0 !== count($spDescriptor)) {
                // we have an IdP
                $spList[] = [
                    'entityId' => $entityId,
                    'AssertionConsumerService' => $this->getAcs($spDescriptor[0]),
                ];
            }
        }

        return $spList;
    }

    public function getIdp($entityId)
    {
        $idpDescriptor = $this->metadata->xpath(sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId));
        if (0 !== count($idpDescriptor)) {
            // we have an IdP
            return [
                'SingleSignOnService' => $this->getSso($idpDescriptor[0]),
                'keys' => $this->getKeys($idpDescriptor[0]),
            ];
        }

        return false;
    }

    public function getSp($entityId)
    {
        $spDescriptor = $this->metadata->xpath(sprintf('//md:EntityDescriptor[@entityID="%s"]/md:SPSSODescriptor', $entityId));
        if (0 !== count($spDescriptor)) {
            // we have an SP
            return [
                'AssertionConsumerService' => $this->getAcs($spDescriptor[0]),
            ];
        }

        return false;
    }

    private function getAcs(SimpleXMLElement $xml)
    {
        $acsList = [];

        $result = $xml->xpath('md:AssertionConsumerService');
        if (0 === count($result)) {
            throw new ParserException('no AssertionConsumerService');
        }

        foreach ($result as $ep) {
            $acsList[] = [
                'Binding' => (string) $ep['Binding'],
                'Location' => (string) $ep['Location'],
                'index' => (int) $ep['index'],
            ];
        }

        return $acsList;
    }

    private function getSso(SimpleXMLElement $xml)
    {
        $ssoList = [];

        $result = $xml->xpath('md:SingleSignOnService');
        if (0 === count($result)) {
            throw new ParserException('no SingleSignOnService');
        }

        foreach ($result as $ep) {
            $ssoList[] = [
                'Binding' => (string) $ep['Binding'],
                'Location' => (string) $ep['Location'],
            ];
        }

        return $ssoList;
    }

    private function getKeys(SimpleXMLElement $xml)
    {
        $keyList = [];

        $result = $xml->xpath('md:KeyDescriptor');
        if (0 === count($result)) {
            throw new ParserException('no KeyDescriptor');
        }

        foreach ($result as $cd) {
            $key = [
                'type' => 'X509Certificate',
                'X509Certificate' => null,
                'encryption' => false,
                'signing' => false,
            ];

            if (!isset($cd['use'])) {
                $key['encryption'] = true;
                $key['signing'] = true;
            } else {
                $use = (string) $cd['use'];
                $key[$use] = true;
            }

            $certData = (string) $cd->children('http://www.w3.org/2000/09/xmldsig#')->KeyInfo->X509Data->X509Certificate;

            // create a one line certificate
            $key['X509Certificate'] = str_replace(
                [' ', "\t", "\n", "\r", "\0", "\x0B"],
                '',
                $certData
            );

            $keyList[] = $key;
        }

        return $keyList;
    }
}
