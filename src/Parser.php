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

    public function getIdp($entityId)
    {
        $metadata = [
            'SingleSignOnService' => [],
            'keys' => [],
        ];

        $result = $this->metadata->xpath(
            sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:SingleSignOnService', $entityId)
        );

        if (0 === count($result)) {
            // no SingleSignOnService entry for this entityID in metadata
            throw new ParserException('entity not found in metadata, or no SingleSignOnService');
        }

        foreach ($result as $ep) {
            $metadata['SingleSignOnService'][] = [
                'Binding' => (string) $ep['Binding'],
                'Location' => (string) $ep['Location'],
            ];
        }

        $result = $this->metadata->xpath(
            sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/md:KeyDescriptor', $entityId)
        );

        if (0 === count($result)) {
            // no KeyDescriptor entry for this entityID in metadata
            throw new ParserException('entity not found in metadata, or no KeyDescriptor');
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

            // create a oneline certificate
            $key['X509Certificate'] = str_replace(
                [' ', "\t", "\n", "\r", "\0", "\x0B"],
                '',
                $certData
            );

            $metadata['keys'][] = $key;
        }

        return $metadata;
    }

    public function getSp($entityId)
    {
        $metadata = [
            'AssertionConsumerService' => [],
        ];

        $result = $this->metadata->xpath(
            sprintf('//md:EntityDescriptor[@entityID="%s"]/md:SPSSODescriptor/md:AssertionConsumerService', $entityId)
        );

        if (0 === count($result)) {
            // no AssertionConsumerService entry for this entityID in metadata
            throw new ParserException('entity not found in metadata, or no AssertionConsumerService');
        }

        foreach ($result as $ep) {
            $metadata['AssertionConsumerService'][] = [
                'Binding' => (string) $ep['Binding'],
                'Location' => (string) $ep['Location'],
                'index' => (int) $ep['index'],
            ];
        }

        return $metadata;
    }
}
