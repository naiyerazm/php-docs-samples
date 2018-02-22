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

use Symfony\Component\Console\Tester\CommandTester;

/**
 * Unit Tests for dlp commands.
 */
class dlpTest extends \PHPUnit_Framework_TestCase
{
    public function checkEnv($var)
    {
        if (!getenv($var)) {
            $this->markTestSkipped('Set the ' . $var . ' environment variable');
        }
    }

    public function setUp()
    {
        $this->checkEnv('GOOGLE_APPLICATION_CREDENTIALS');
    }

    public function testInspectDatastore()
    {
        $this->markTestSkipped();
        $output = $this->runCommand('inspect-datastore', [
            'kind' => 'Book',
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
        ]);
        $this->assertContains('US_CENSUS_NAME', $output);
    }

    public function testInspectBigquery()
    {
        $this->markTestSkipped();
        $output = $this->runCommand('inspect-bigquery', [
            'dataset' => 'integration_tests_dlp',
            'table' => 'harmful',
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'table-project' => getenv('GOOGLE_PROJECT_ID'),
        ]);
        $this->assertContains('CREDIT_CARD_NUMBER', $output);
    }

    public function testInspectFile()
    {
        // inspect a text file with results
        $output = $this->runCommand('inspect-file', [
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'path' => __DIR__ . '/data/test.txt'
        ]);
        $this->assertContains('US_CENSUS_NAME', $output);
        $this->assertContains('Very likely', $output);

        // inspect an image file with results
        $output = $this->runCommand('inspect-file', [
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'path' => __DIR__ . '/data/test.png'
        ]);
        $this->assertContains('US_CENSUS_NAME', $output);
        $this->assertContains('Very likely', $output);

        // inspect a file with no results
        $output = $this->runCommand('inspect-file', [
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'path' => __DIR__ . '/data/harmless.txt'
        ]);
        $this->assertContains('No findings', $output);
    }

    public function testInspectString()
    {
        // inspect a string with results
        $output = $this->runCommand('inspect-string', [
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'string' => 'The name Robert is very common.'
        ]);
        $this->assertContains('US_CENSUS_NAME', $output);
        $this->assertContains('Very likely', $output);

        // inspect a string with no results
        $output = $this->runCommand('inspect-string', [
            'calling-project' => getenv('GOOGLE_PROJECT_ID'),
            'string' => 'The name Zolo is not very common.'
        ]);
        $this->assertContains('No findings', $output);
    }

    public function testListInfoTypes()
    {
        $this->markTestSkipped();

        // list all info types
        $output = $this->runCommand('list-info-types');
        $this->assertContains('US_DEA_NUMBER', $output);
        $this->assertContains('AMERICAN_BANKERS_CUSIP_ID', $output);

        // list info types with a filter
        $output = $this->runCommand('list-info-types', [
            'filter' => 'supported_by=RISK_ANALYSIS'
        ]);

        $this->assertContains('US_DEA_NUMBER', $output);
        $this->assertNotContains('AMERICAN_BANKERS_CUSIP_ID', $output);
    }

    public function testRedactImage()
    {
        var_dump(getcwd());
        $output = $this->runCommand('redact-image', [
            'image-path' => dirname(__FILE__) . '/data/test.png',
            'output-path' => dirname(__FILE__) . '/data/redact.output.png'
        ]);
        $this->assertEquals(
            sha1_file(dirname(__FILE__) . '/data/redact.output.png'),
            sha1_file(dirname(__FILE__) . '/data/redact.correct.png')
        );
    }

    public function testDeidentifyMask()
    {
        $output = $this->runCommand('deidentify-mask', [
            'string' => 'My SSN is 372819127.',
            'number-to-mask' => 5
        ]);
        $this->assertContains('My SSN is xxxxx9127', $output);
    }

    public function testDeidReidFPE()
    {
        $this->checkEnv('DLP_DEID_KEY_NAME');
        $this->checkEnv('DLP_DEID_WRAPPED_KEY');

        $output = $this->runCommand('deidentify-fpe', [
            'string' => 'My SSN is 372819127.',
            'wrapped-key' => getEnv('DLP_DEID_WRAPPED_KEY'),
            'key-name' => getEnv('DLP_DEID_KEY_NAME')
        ]);
        $this->assertRegExp('/My SSN is SSN_TOKEN\(9\):\d+/', $output);
    }

    private function runCommand($commandName, $args = [])
    {
        $application = require __DIR__ . '/../dlp.php';
        $command = $application->get($commandName);
        $commandTester = new CommandTester($command);

        ob_start();
        $commandTester->execute(
            $args,
            ['interactive' => false]);

        return ob_get_clean();
    }
}
