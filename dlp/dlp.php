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

require __DIR__ . '/vendor/autoload.php';

use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;

$application = new Application('Cloud DLP');

$application->add(new Command('inspect-string'))
    ->addArgument('string', InputArgument::REQUIRED, 'The text to inspect')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->setDescription('Inspect a string using the Data Loss Prevention (DLP) API.')
    ->addArgument('max-findings',
        InputArgument::OPTIONAL,
        'The maximum number of findings to report per request (0 = server maximum)',
        0)
    ->setCode(function ($input, $output) {
        inspect_string(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('string')
        );
    });

$application->add(new Command('inspect-file'))
    ->addArgument('path', InputArgument::REQUIRED, 'The file path to inspect')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->setDescription('Inspect a file using the Data Loss Prevention (DLP) API.')
    ->addArgument('max-findings',
        InputArgument::OPTIONAL,
        'The maximum number of findings to report per request (0 = server maximum)',
        0)
    ->setCode(function ($input, $output) {
        inspect_file(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('path')
        );
    });

$application->add(new Command('inspect-datastore'))
    ->addArgument('kind', InputArgument::REQUIRED, 'The Datastore kind to inspect')
    ->addArgument('namespace', InputArgument::OPTIONAL, 'The Datastore Namespace ID to inspect')
    ->addArgument('datastore-project', InputArgument::OPTIONAL, 'The GCP Project ID that the Datastore exists under', getenv('GOOGLE_PROJECT_ID'))
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->addArgument('max-findings',
        InputArgument::OPTIONAL,
        'The maximum number of findings to report per request (0 = server maximum)',
        0)
    ->setDescription('Inspect Cloud Datastore using the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        inspect_datastore(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('kind'),
            (string) $input->getArgument('namespace'),
            (int) $input->getArgument('max-findings')
        );
    });

$application->add(new Command('inspect-bigquery'))
    ->addArgument('dataset', InputArgument::REQUIRED, 'The ID of the dataset to inspect')
    ->addArgument('table', InputArgument::REQUIRED, 'The ID of the table to inspect')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->addArgument('max-findings',
        InputArgument::OPTIONAL,
        'The maximum number of findings to report per request (0 = server maximum)',
        0)
    ->setDescription('Inspect a BigQuery table using the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        inspect_bigquery(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('dataset'),
            $input->getArgument('table'),
            (int) $input->getArgument('max-findings')
        );
    });

$application->add(new Command('list-info-types'))
    ->addArgument('filter', InputArgument::OPTIONAL, 'The filter to use', '')
    ->addArgument('language-code', InputArgument::OPTIONAL, 'The text to inspect', '')
    ->setDescription('Lists all Info Types for the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        list_info_types(
            $input->getArgument('filter'),
            $input->getArgument('language-code')
        );
    });

$application->add(new Command('redact-image'))
    ->addArgument('image-path', InputArgument::REQUIRED, 'The filepath of the image to inspect')
    ->addArgument('output-path', InputArgument::REQUIRED, 'The local path to save the resulting image to')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->setDescription('Redact sensitive data from an image using the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        redact_image(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('image-path'),
            $input->getArgument('output-path')
        );
    });

$application->add(new Command('deidentify-mask'))
    ->addArgument('string', InputArgument::REQUIRED, 'The text to deidentify')
    ->addArgument('number-to-mask',
        InputArgument::OPTIONAL,
        'The maximum number of sensitive characters to mask in a match',
        0)
    ->addArgument('masking-character',
        InputArgument::OPTIONAL,
        'The character to mask matching sensitive data with',
        'x')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->setDescription('Mask sensitive data in a string using the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        deidentify_mask(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('string'),
            (int) $input->getArgument('number-to-mask'),
            $input->getArgument('masking-character')
        );
    });

$application->add(new Command('deidentify-fpe'))
    ->addArgument('string', InputArgument::REQUIRED, 'The text to deidentify')
    ->addArgument('key-name',
        InputArgument::REQUIRED,
        'The name of the Cloud KMS key used to encrypt ("wrap") the AES-256 key')
    ->addArgument('wrapped-key',
        InputArgument::REQUIRED,
        'The AES-256 key to use, encrypted ("wrapped") with the KMS key defined by $keyName.')
    ->addArgument('surrogate-type', InputArgument::OPTIONAL, 'The name of the surrogate custom info type to use when reidentifying')
    ->addArgument('calling-project', InputArgument::OPTIONAL, 'The GCP Project ID to run the API call under', getenv('GOOGLE_PROJECT_ID'))
    ->setDescription('Mask sensitive data in a string using the Data Loss Prevention (DLP) API.')
    ->setCode(function ($input, $output) {
        deidentify_fpe(
            (string) $input->getArgument('calling-project'),
            $input->getArgument('string'),
            (int) $input->getArgument('key-name'),
            $input->getArgument('wrapped-key')
        );
    });

// for testing
if (getenv('PHPUNIT_TESTS') === '1') {
    return $application;
}

$application->run();
