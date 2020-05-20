#!/usr/bin/env python3

import unittest
from unittest import TestLoader, TestSuite
from HtmlTestRunner import HTMLTestRunner

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from autoVAS import *

# Documentation for unittest
# https://docs.python.org/3/library/unittest.html#module-unittest

class AutoVASTestClass(unittest.TestCase):
	maxDiff = None

	def setUp(self):
		self.av = AutoVAS()

	def tearDown(self):
		del self.av

	def test_GivenNormalInput_WhenCallParseAndQuery_ThenReturnSuccess(self):
		self.av.autoVAS_parse('/home/kevin/works/autoVAS/dataset/source/NVD/cve-2004-1151')
		result = self.av.autoVAS_query('cpg.method.name.toSet')
		expect = 'Set(CVE_2004_1151_PATCHED_sys32_ni_syscall, strncmp, <operator>.minus, strncpy, strcpy, <operator>.indirectMemberAccess, <operator>.assignment, CVE_2004_1151_VULN_sys32_ni_syscall, <operator>.sizeOf, strcmp)'
		self.assertEqual(result, expect)
		result = self.av.autoVAS_query('cpg.local.name.toSet')
		expect = 'Set(lastcomm, me)'
		self.assertEqual(result, expect)

	def test_GivenAbnormalInput_WhenCallParseAndQuery_ThenReturnFail(self):
		self.av.autoVAS_parse('/home/kevin/works/autoVAS/dataset/source/NVD/cve-2004-1151')
		result = self.av.autoVAS_query('cpp.method.nnn')
		expect = 'Set(CVE_2004_1151_PATCHED_sys32_ni_syscall, strncmp, <operator>.minus, strncpy, strcpy, <operator>.indirectMemberAccess, <operator>.assignment, CVE_2004_1151_VULN_sys32_ni_syscall, <operator>.sizeOf, strcmp)'
		self.assertNotEqual(result, expect)

if __name__ == '__main__':
	test = TestLoader().loadTestsFromTestCase(AutoVASTestClass)
	suite = TestSuite([test])
	runner = HTMLTestRunner(output='report',
			report_name='AutoVAS_TestReport', 
			report_title='AutoVAS Test Report',
			combine_reports = True)
	runner.run(suite)
	#unittest.main()
	#runner = unittest.TextTestRunner()
	#runner.run(unittest.makeSuite(AutoVASTestClass, 'test'))
