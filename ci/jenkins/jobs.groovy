// Job DSL seed for the contract Jenkins (loaded by casc.yaml). One pipeline per masking pattern.
def report = "cp /fixtures/tests/fixtures/semgrep/semgrep-findings.json semgrep.json"
def pipelines = [
  'sast-ok': """
    pipeline { agent any; stages {
      stage('Scan') { steps { sh '${report}'; archiveArtifacts artifacts: 'semgrep.json' } }
    } }""",
  // catchError keeps the BUILD green while the STAGE is marked failed
  'sast-masked': """
    pipeline { agent any; stages {
      stage('Scan') { steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') { sh 'exit 2' }
        sh '${report}'; archiveArtifacts artifacts: 'semgrep.json'
      } }
    } }""",
  'sast-unstable': """
    pipeline { agent any; stages {
      stage('Scan') { steps {
        warnError('scanner reported problems') { sh 'exit 1' }
        sh '${report}'; archiveArtifacts artifacts: 'semgrep.json'
      } }
    } }""",
  'sast-skipped': """
    pipeline { agent any; stages {
      stage('Scan') { when { expression { return false } }; steps { sh 'true' } }
      stage('Build') { steps { sh 'true' } }
    } }""",
  'sast-failed': """
    pipeline { agent any; stages {
      stage('Scan') { steps { sh 'exit 1' } }
    } }""",
  'sast-parallel': """
    pipeline { agent any; stages {
      stage('Scans') { parallel {
        stage('sast-python') { steps { sh 'mkdir -p py && ${report} && mv semgrep.json py/'; archiveArtifacts artifacts: 'py/semgrep.json' } }
        stage('sast-go') { steps { catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') { sh 'exit 1' } } }
      } }
    } }""",
  'sast-matrix': """
    pipeline { agent any; stages {
      stage('Scan') { matrix {
        axes { axis { name 'LANG'; values 'python', 'go' } }
        stages { stage('sast') { steps {
          script { if (env.LANG == 'go') { catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') { sh 'exit 1' } } }
          sh "mkdir -p \\\$LANG && ${report} && mv semgrep.json \\\$LANG/"
          archiveArtifacts artifacts: "\${env.LANG}/semgrep.json"
        } } }
      } }
    } }""",
  'sast-retry': """
    pipeline { agent any; stages {
      stage('Scan') { steps {
        retry(2) { sh 'if [ ! -f .tried ]; then touch .tried; exit 1; fi' }
        sh '${report}'; archiveArtifacts artifacts: 'semgrep.json'
      } }
    } }""",
  // scripted try/catch: the error is swallowed by user code
  'sast-trycatch': """
    node { stage('Scan') {
      try { sh 'exit 3' } catch (err) { echo "ignored: \${err}" }
      sh '${report}'; archiveArtifacts artifacts: 'semgrep.json'
    } }""",
]
pipelines.each { name, body ->
  pipelineJob(name) { definition { cps { script(body.stripIndent()); sandbox(true) } } }
}
