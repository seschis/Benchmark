/**
 * OWASP Benchmark Project
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Benchmark Project For details, please see
 * <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
 *
 * The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details
 *
 * @author Dave Wichers <a href="https://www.aspectsecurity.com">Aspect Security</a>
 * @created 2015
 */

package org.owasp.benchmark.score.parsers;

import com.contrastsecurity.sarif.CodeFlow;
import com.contrastsecurity.sarif.Result;

import java.io.File;
import java.text.SimpleDateFormat;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.ObjectMapper;



public class ContrastScanReader extends Reader {
	private static final Pattern ResultNamePattern = Pattern.compile(".*? BenchmarkTest(\\d\\d\\d\\d\\d)\\.java.*");

	public static void main(String[] args) throws Exception {
		File f = new File("results/Benchmark_1.2-ContrastScan.contrastscan.sarif");
		ContrastScanReader cr = new ContrastScanReader();
		cr.parse(f);
	}

	
	public TestResults parse(File f) throws Exception {
		ObjectMapper objectMapper = new ObjectMapper();
		TestResults tr = new TestResults("Contrast Scan", true, TestResults.ToolType.SAST);
		SarifSchema210 sarif = objectMapper.readValue(f, SarifSchema210.class);
		List<Result> sarifResults = sarif.getRuns().get(0).getResults();
		tr.setToolVersion(sarif.getRuns().get(0).getTool().getDriver().getVersion());
		Date start = sarif.getRuns().get(0).getInvocations().get(0).getStartTimeUtc();
		Date end = sarif.getRuns().get(0).getInvocations().get(0).getEndTimeUtc();
		Math.abs(end.getTime() - start.getTime());
		tr.setTime(TestResults.formatTime(Math.abs(end.getTime() - start.getTime())));

		for (Result r : sarifResults) {
			String ruleId = r.getRuleId();
			CodeFlow cf = r.getCodeFlows().get(0);
			String message = cf.getMessage().getText();
			Integer testNum = extractTestNum(message);
			TestCaseResult tcr = new TestCaseResult();
			tcr.setCWE(cweLookup(ruleId));
			tcr.setCategory(ruleId);
			tcr.setNumber(testNum);
			if (tcr.getCWE() != 0) {
				tr.put(tcr);
			}
		}
		return tr;
	}

	private static Integer extractTestNum(String msg) {
		// extract benchmark name in the form:
		// Found tainted data flow from BenchmarkTest01870.java:100...
		Matcher m = ResultNamePattern.matcher(msg);
		if (!m.matches()) {
			return -1;
		}
		String name = m.group(1);

		return Integer.parseInt(name);
	}


    
	private static int cweLookup(String rule) {
		switch (rule) {
		case "cookie-flags-missing":
			return 614; // insecure cookie use
		case "sql-injection":
			return 89; // sql injection
		case "cmd-injection":
			return 78; // command injection
		case "ldap-injection":
			return 90; // ldap injection
		case "header-injection":
			return 113; // header injection
		case "hql-injection":
			return 564; // hql injection
		case "unsafe-readline":
			return 0000; // unsafe readline
		case "reflection-injection":
			return 0000; // reflection injection
		case "reflected-xss":
			return 79; // xss
		case "xpath-injection":
			return 643; // xpath injection
		case "path-traversal":
			return 22; // path traversal
		case "crypto-bad-mac":
			return 328; // weak hash
		case "crypto-weak-randomness":
			return 330; // weak random
		case "crypto-bad-ciphers":
			return 327; // weak encryption
		case "trust-boundary-violation":
			return 501; // trust boundary
		case "xxe":
			return 611; // xml entity
		}
		return 0;
	}

	private String calculateTime(String firstLine, String lastLine) {
		try {
			String start = firstLine.split(" ")[1];
			String stop = lastLine.split(" ")[1];
			SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss,SSS");
			Date startTime = sdf.parse(start);
			Date stopTime = sdf.parse(stop);
			long startMillis = startTime.getTime();
			long stopMillis = stopTime.getTime();
			long seconds = (stopMillis - startMillis) / 1000;
			return seconds + " seconds";
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
