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

# [START inspect_string]
use Google\Cloud\Dlp\V2beta2\DlpServiceClient;
use Google\Cloud\Dlp\V2beta2\ContentItem;
use Google\Cloud\Dlp\V2beta2\InfoType;
use Google\Cloud\Dlp\V2beta2\InspectConfig;
use Google\Cloud\Dlp\V2beta2\Likelihood;
use Google\Cloud\Dlp\V2beta2\InspectConfig_FindingLimits;

/**
 * Inspect a string using the Data Loss Prevention (DLP) API.
 *
 * @param string $string The text to inspect
 */
function inspect_string(
    $callingProject,
    $string,
    $minLikelihood = likelihood::LIKELIHOOD_UNSPECIFIED,
    $maxFindings = 0)
{
    // Instantiate a client.
    $dlp = new DlpServiceClient();

    // The infoTypes of information to match
    $usNameInfoType = new InfoType();
    $usNameInfoType->setName('US_CENSUS_NAME');
    $usStateInfoType = new InfoType();
    $usStateInfoType->setName('US_STATE');
    $infoTypes = [$usNameInfoType, $usStateInfoType];

    // Whether to include the matching string in the response
    $includeQuote = true;

    // Specify finding limits
    $limits = new InspectConfig_FindingLimits(); // TODO blech...can we make this a dot property?
    $limits->setMaxFindingsPerRequest($maxFindings);

    // Create the configuration object
    $inspectConfig = new InspectConfig();
    $inspectConfig->setMinLikelihood($minLikelihood);
    $inspectConfig->setLimits($limits);
    $inspectConfig->setInfoTypes($infoTypes);
    $inspectConfig->setIncludeQuote($includeQuote);

    $content = new ContentItem();
    $content->setType('text/plain');
    $content->setValue($string);

    $parent = $dlp->projectName($callingProject);

    // Run request
    $response = $dlp->inspectContent($parent, Array(
        'inspectConfig' => $inspectConfig,
        'item' => $content
    ));

    $likelihoods = ['Unknown', 'Very unlikely', 'Unlikely', 'Possible',
                    'Likely', 'Very likely'];

    // Print the results
    $findings = $response->getResult()->getFindings();
    if (count($findings) == 0) {
        print('No findings.' . PHP_EOL);
    } else {
        print('Findings:' . PHP_EOL);
        foreach ($findings as $finding) {
            if ($includeQuote) {
                print('  Quote: ' . $finding->getQuote() . PHP_EOL);
            }
            print('  Info type: ' . $finding->getInfoType()->getName() . PHP_EOL);
            $likelihoodString = $likelihoods[$finding->getLikelihood()];
            print('  Likelihood: ' . $likelihoodString . PHP_EOL);
        }
    }
}
# [END inspect_string]
