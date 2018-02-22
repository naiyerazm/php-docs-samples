<?php

/**
 * Copyright 2016 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace Google\Cloud\Samples\Dlp;

# [START redact_string]
use Google\Cloud\Dlp\V2beta2\DlpServiceClient;
use Google\Cloud\Dlp\V2beta2\ContentItem;
use Google\Cloud\Dlp\V2beta2\InfoType;
use Google\Cloud\Dlp\V2beta2\InspectConfig;
use Google\Cloud\Dlp\V2beta2\InspectConfig_FindingLimits;
use Google\Cloud\Dlp\V2beta2\RedactImageRequest_ImageRedactionConfig;
use Google\Cloud\Dlp\V2beta2\Likelihood;

/**
 * Redact a sensitive string using the Data Loss Prevention (DLP) API.
 *
 * @param string $string The text to inspect
 */
function redact_image(
    $callingProjectId,
    $imagePath,
    $outputPath,
    $minLikelihood = likelihood::LIKELIHOOD_UNSPECIFIED)
{
    // Instantiate a client.
    $dlp = new DlpServiceClient();

    // The infoTypes of information to match
    $phoneNumberInfoType = new InfoType();
    $phoneNumberInfoType->setName('PHONE_NUMBER');
    $infoTypes = [$phoneNumberInfoType];

    // Whether to include the matching string in the response
    $includeQuote = true;

    // Create the configuration object
    $inspectConfig = new InspectConfig();
    $inspectConfig->setMinLikelihood($minLikelihood);
    $inspectConfig->setInfoTypes($infoTypes);

    // Read image file into a buffer
    $imageRef = fopen($imagePath, 'rb');
    $imageBytes = fread($imageRef, filesize($imagePath));
    fclose($imageRef);
    $imageType = mime_content_type($imagePath);

    $content = new ContentItem();
    $content->setType($imageType);
    $content->setData($imageBytes);

    $imageRedactionConfigs = [];
    foreach ($infoTypes as $infoType) {
        $config = new RedactImageRequest_ImageRedactionConfig();
        $config->setInfoType($infoType);
        $imageRedactionConfigs[] = $config;
    }

    $parent = $dlp->projectName($callingProjectId);

    // Run request
    $response = $dlp->redactImage($parent, Array(
        'inspectConfig' => $inspectConfig,
        'imageType' => $imageType,
        'imageData' => $imageBytes,
        'imageRedactionConfigs' => $imageRedactionConfigs
    ));

    // Save result to file
    $outputRef = fopen($outputPath, 'wb');
    fwrite($outputRef, $response->getRedactedImage());
    fclose($outputRef);

    // Print completion message
    print('Redacted image saved to ' . $outputPath . PHP_EOL);
}
# [END redact_string]
