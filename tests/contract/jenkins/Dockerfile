# Throwaway Jenkins for ScanProof's live Jenkins contract (.github/workflows/platforms-contract.yml).
# Never published. The LTS version used is recorded in the collected fixtures.
FROM jenkins/jenkins:lts-jdk21
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false" CASC_JENKINS_CONFIG=/var/jenkins_home/casc.yaml
RUN jenkins-plugin-cli --plugins workflow-aggregator pipeline-stage-view pipeline-graph-view \
    configuration-as-code job-dsl
COPY casc.yaml jobs.groovy /var/jenkins_home/
