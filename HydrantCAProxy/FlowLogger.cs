// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.  You may obtain a
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
// required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for
// the specific language governing permissions and limitations under the
// License.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Keyfactor.HydrantId
{
    public sealed class FlowLogger : IDisposable
    {
        private readonly ILogger _logger;
        private readonly string _flowName;
        private readonly List<FlowStep> _steps = new List<FlowStep>();
        private readonly Stopwatch _stopwatch;

        public FlowLogger(ILogger logger, string flowName)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _flowName = flowName ?? "Unknown";
            _stopwatch = Stopwatch.StartNew();
            _logger.LogDebug("===== FLOW START: {FlowName} =====", _flowName);
        }

        public void Step(string name, string detail = null)
        {
            _steps.Add(new FlowStep(name, FlowStepStatus.Ok, detail));
            _logger.LogDebug("[FLOW] {FlowName} -> {StepName}: {Detail}", _flowName, name, detail ?? "OK");
        }

        public void Step(string name, Action action)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                action();
                sw.Stop();
                _steps.Add(new FlowStep(name, FlowStepStatus.Ok, $"{sw.ElapsedMilliseconds}ms"));
                _logger.LogDebug("[FLOW] {FlowName} -> {StepName}: OK ({Elapsed}ms)", _flowName, name, sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                _steps.Add(new FlowStep(name, FlowStepStatus.Failed, ex.Message));
                _logger.LogWarning("[FLOW] {FlowName} -> {StepName}: FAILED - {Error}", _flowName, name, ex.Message);
                throw;
            }
        }

        public async Task StepAsync(string name, Func<Task> action)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                await action();
                sw.Stop();
                _steps.Add(new FlowStep(name, FlowStepStatus.Ok, $"{sw.ElapsedMilliseconds}ms"));
                _logger.LogDebug("[FLOW] {FlowName} -> {StepName}: OK ({Elapsed}ms)", _flowName, name, sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                _steps.Add(new FlowStep(name, FlowStepStatus.Failed, ex.Message));
                _logger.LogWarning("[FLOW] {FlowName} -> {StepName}: FAILED - {Error}", _flowName, name, ex.Message);
                throw;
            }
        }

        public void Fail(string name, string reason)
        {
            _steps.Add(new FlowStep(name, FlowStepStatus.Failed, reason));
            _logger.LogWarning("[FLOW] {FlowName} -> {StepName}: FAILED - {Reason}", _flowName, name, reason);
        }

        public void Skip(string name, string reason)
        {
            _steps.Add(new FlowStep(name, FlowStepStatus.Skipped, reason));
            _logger.LogDebug("[FLOW] {FlowName} -> {StepName}: SKIPPED - {Reason}", _flowName, name, reason);
        }

        public void Dispose()
        {
            _stopwatch.Stop();
            var hasFailure = false;

            _logger.LogDebug("===== FLOW DIAGRAM: {FlowName} =====", _flowName);
            foreach (var step in _steps)
            {
                string icon;
                switch (step.Status)
                {
                    case FlowStepStatus.Ok:
                        icon = "[OK]";
                        break;
                    case FlowStepStatus.Failed:
                        icon = "[FAIL]";
                        hasFailure = true;
                        break;
                    case FlowStepStatus.Skipped:
                        icon = "[SKIP]";
                        break;
                    default:
                        icon = "[...]";
                        break;
                }

                var detail = string.IsNullOrEmpty(step.Detail) ? "" : $" ({step.Detail})";
                _logger.LogDebug("  | {Icon} {StepName}{Detail}", icon, step.Name, detail);
                _logger.LogDebug("  v");
            }

            var result = hasFailure ? "PARTIAL FAILURE" : "SUCCESS";
            _logger.LogDebug("===== FLOW RESULT: {Result} ({Elapsed}ms) =====", result, _stopwatch.ElapsedMilliseconds);
        }

        private enum FlowStepStatus
        {
            Ok,
            Failed,
            Skipped
        }

        private class FlowStep
        {
            public string Name { get; }
            public FlowStepStatus Status { get; }
            public string Detail { get; }

            public FlowStep(string name, FlowStepStatus status, string detail)
            {
                Name = name;
                Status = status;
                Detail = detail;
            }
        }
    }
}
