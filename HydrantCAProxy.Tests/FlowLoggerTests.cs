// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keyfactor.HydrantId;
using Microsoft.Extensions.Logging;
using Xunit;

namespace HydrantCAProxy.Tests
{
    public class FlowLoggerTests
    {
        // A minimal ILogger test double that records the formatted message of every
        // Log call, so assertions can check FlowLogger's actual output content instead
        // of just "no exception was thrown."
        private sealed class RecordingLogger : ILogger
        {
            public List<string> Messages { get; } = new List<string>();

            public IDisposable BeginScope<TState>(TState state) => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
            {
                Messages.Add(formatter(state, exception));
            }
        }

        [Fact]
        public void Constructor_NullLogger_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new FlowLogger(null, "Test"));
        }

        [Fact]
        public void Constructor_NullFlowName_DefaultsToUnknown()
        {
            var logger = new RecordingLogger();

            using var flow = new FlowLogger(logger, null);

            Assert.Contains(logger.Messages, m => m.Contains("Unknown"));
        }

        [Fact]
        public void Step_WithDetail_LogsDetail()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            flow.Step("MyStep", "some detail");

            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("some detail"));
        }

        [Fact]
        public void Step_NullDetail_LogsOk()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            flow.Step("MyStep");

            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("OK"));
        }

        [Fact]
        public void Step_ActionSucceeds_LogsOk()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");
            var ran = false;

            flow.Step("MyStep", () => { ran = true; });

            Assert.True(ran);
            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("OK"));
        }

        [Fact]
        public void Step_ActionThrows_LogsFailureAndRethrows()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            var ex = Assert.Throws<InvalidOperationException>(() =>
                flow.Step("MyStep", () => throw new InvalidOperationException("boom")));

            Assert.Equal("boom", ex.Message);
            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("FAILED") && m.Contains("boom"));
        }

        [Fact]
        public async Task StepAsync_ActionSucceeds_LogsOk()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");
            var ran = false;

            await flow.StepAsync("MyStep", async () =>
            {
                await Task.Delay(1);
                ran = true;
            });

            Assert.True(ran);
            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("OK"));
        }

        [Fact]
        public async Task StepAsync_ActionThrows_LogsFailureAndRethrows()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                flow.StepAsync("MyStep", () => throw new InvalidOperationException("async boom")));

            Assert.Equal("async boom", ex.Message);
            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("FAILED") && m.Contains("async boom"));
        }

        [Fact]
        public void Fail_LogsFailedWithReason()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            flow.Fail("MyStep", "went wrong");

            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("FAILED") && m.Contains("went wrong"));
        }

        [Fact]
        public void Skip_LogsSkippedWithReason()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");

            flow.Skip("MyStep", "not needed");

            Assert.Contains(logger.Messages, m => m.Contains("MyStep") && m.Contains("SKIPPED") && m.Contains("not needed"));
        }

        [Fact]
        public void Dispose_NoFailures_LogsSuccessSummary()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");
            flow.Step("Step1", "ok");
            flow.Skip("Step2", "skipped");

            flow.Dispose();

            Assert.Contains(logger.Messages, m => m.Contains("FLOW DIAGRAM"));
            Assert.Contains(logger.Messages, m => m.Contains("[OK]") && m.Contains("Step1"));
            Assert.Contains(logger.Messages, m => m.Contains("[SKIP]") && m.Contains("Step2"));
            Assert.Contains(logger.Messages, m => m.Contains("SUCCESS"));
        }

        [Fact]
        public void Dispose_WithFailure_LogsPartialFailureSummary()
        {
            var logger = new RecordingLogger();
            var flow = new FlowLogger(logger, "Test");
            flow.Fail("Step1", "broke");

            flow.Dispose();

            Assert.Contains(logger.Messages, m => m.Contains("[FAIL]") && m.Contains("Step1"));
            Assert.Contains(logger.Messages, m => m.Contains("PARTIAL FAILURE"));
        }
    }
}
