//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apereo.cas.web.flow.configurer;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;
import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.RememberMeUsernamePasswordCredential;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.adaptive.UnauthorizedAuthenticationException;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.exceptions.InvalidLoginLocationException;
import org.apereo.cas.authentication.exceptions.InvalidLoginTimeException;
import org.apereo.cas.authentication.principal.Response.ResponseType;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apereo.cas.services.UnauthorizedSsoServiceException;
import org.apereo.cas.ticket.UnsatisfiedAuthenticationPolicyException;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.action.SetAction;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.ActionState;
import org.springframework.webflow.engine.EndState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.BinderConfiguration.Binding;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.support.TransitionExecutingFlowExecutionExceptionHandler;
import org.springframework.webflow.execution.repository.NoSuchFlowExecutionException;

public class DefaultWebflowConfigurer extends AbstractCasWebflowConfigurer {
    public DefaultWebflowConfigurer(FlowBuilderServices flowBuilderServices, FlowDefinitionRegistry flowDefinitionRegistry, ApplicationContext applicationContext, CasConfigurationProperties casProperties) {
        super(flowBuilderServices, flowDefinitionRegistry, applicationContext, casProperties);
    }

    protected void doInitialize() {
        Flow flow = this.getLoginFlow();
        if (flow != null) {
            this.createInitialFlowActions(flow);
            this.createDefaultGlobalExceptionHandlers(flow);
            this.createDefaultEndStates(flow);
            this.createDefaultDecisionStates(flow);
            this.createDefaultActionStates(flow);
            this.createDefaultViewStates(flow);
            this.createRememberMeAuthnWebflowConfig(flow);
        }

    }

    protected void createInitialFlowActions(Flow flow) {
        flow.getStartActionList().add(this.createEvaluateAction("initialFlowSetupAction"));
    }

    protected void createDefaultViewStates(Flow flow) {
        this.createAuthenticationWarningMessagesView(flow);
    }

    protected void createAuthenticationWarningMessagesView(Flow flow) {
        ViewState state = this.createViewState(flow, "showAuthenticationWarningMessages", "casLoginMessageView");
        SetAction setAction = new SetAction(this.createExpression("requestScope.messages"), this.createExpression("messageContext.allMessages"));
        state.getEntryActionList().add(setAction);
        this.createTransitionForState(state, "proceed", "proceedFromAuthenticationWarningView");
        ActionState proceedAction = this.createActionState(flow, "proceedFromAuthenticationWarningView");
        proceedAction.getActionList().add(this.createEvaluateAction("sendTicketGrantingTicketAction"));
        this.createStateDefaultTransition(proceedAction, "serviceCheck");
    }

    protected void createRememberMeAuthnWebflowConfig(Flow flow) {
        if (this.casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            this.createFlowVariable(flow, "credential", RememberMeUsernamePasswordCredential.class);
            ViewState state = (ViewState)this.getState(flow, "viewLoginForm", ViewState.class);
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new Binding("rememberMe", (String)null, false));
        } else {
            this.createFlowVariable(flow, "credential", UsernamePasswordCredential.class);
            ViewState state = (ViewState)this.getState(flow, "viewLoginForm", ViewState.class);
            BinderConfiguration cfg = this.getViewStateBinderConfiguration(state);
            cfg.addBinding(new Binding("capcha", (String)null, true));
        }

    }

    protected void createDefaultActionStates(Flow flow) {
        this.createSendTicketGrantingTicketAction(flow);
        this.createGenerateServiceTicketAction(flow);
        this.createTerminateSessionAction(flow);
        this.createGatewayServicesMgmtAction(flow);
        this.createServiceAuthorizationCheckAction(flow);
        this.createRedirectToServiceActionState(flow);
        this.createHandleAuthenticationFailureAction(flow);
    }

    private void createSendTicketGrantingTicketAction(Flow flow) {
        ActionState action = this.createActionState(flow, "sendTicketGrantingTicket", this.createEvaluateAction("sendTicketGrantingTicketAction"));
        this.createTransitionForState(action, "success", "serviceCheck");
    }

    protected void createGenerateServiceTicketAction(Flow flow) {
        ActionState handler = this.createActionState(flow, "generateServiceTicket", this.createEvaluateAction("generateServiceTicketAction"));
        this.createTransitionForState(handler, "success", "redirect");
        this.createTransitionForState(handler, "warn", "warn");
        this.createTransitionForState(handler, "authenticationFailure", "handleAuthenticationFailure");
        this.createTransitionForState(handler, "error", "initializeLoginForm");
        this.createTransitionForState(handler, "gateway", "gatewayServicesManagementCheck");
    }

    protected void createHandleAuthenticationFailureAction(Flow flow) {
        ActionState handler = this.createActionState(flow, "handleAuthenticationFailure", this.createEvaluateAction("authenticationExceptionHandler"));
        this.createTransitionForState(handler, AccountDisabledException.class.getSimpleName(), "casAccountDisabledView");
        this.createTransitionForState(handler, AccountLockedException.class.getSimpleName(), "casAccountLockedView");
        this.createTransitionForState(handler, AccountPasswordMustChangeException.class.getSimpleName(), "casMustChangePassView");
        this.createTransitionForState(handler, CredentialExpiredException.class.getSimpleName(), "casExpiredPassView");
        this.createTransitionForState(handler, InvalidLoginLocationException.class.getSimpleName(), "casBadWorkstationView");
        this.createTransitionForState(handler, InvalidLoginTimeException.class.getSimpleName(), "casBadHoursView");
        this.createTransitionForState(handler, FailedLoginException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(handler, AccountNotFoundException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(handler, UnauthorizedServiceForPrincipalException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(handler, PrincipalException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(handler, UnsatisfiedAuthenticationPolicyException.class.getSimpleName(), "initializeLoginForm");
        this.createTransitionForState(handler, UnauthorizedAuthenticationException.class.getSimpleName(), "casAuthenticationBlockedView");
        this.createTransitionForState(handler, "serviceUnauthorizedCheck", "serviceUnauthorizedCheck");
        this.createStateDefaultTransition(handler, "initializeLoginForm");
    }

    protected void createRedirectToServiceActionState(Flow flow) {
        ActionState redirectToView = this.createActionState(flow, "redirect", this.createEvaluateAction("redirectToServiceAction"));
        this.createTransitionForState(redirectToView, ResponseType.POST.name().toLowerCase(), "postView");
        this.createTransitionForState(redirectToView, ResponseType.HEADER.name().toLowerCase(), "headerView");
        this.createTransitionForState(redirectToView, ResponseType.REDIRECT.name().toLowerCase(), "redirectView");
    }

    private void createServiceAuthorizationCheckAction(Flow flow) {
        ActionState serviceAuthorizationCheck = this.createActionState(flow, "serviceAuthorizationCheck", this.createEvaluateAction("serviceAuthorizationCheck"));
        this.createStateDefaultTransition(serviceAuthorizationCheck, "initializeLoginForm");
    }

    protected void createGatewayServicesMgmtAction(Flow flow) {
        ActionState gatewayServicesManagementCheck = this.createActionState(flow, "gatewayServicesManagementCheck", this.createEvaluateAction("gatewayServicesManagementCheck"));
        this.createTransitionForState(gatewayServicesManagementCheck, "success", "redirect");
    }

    protected void createTerminateSessionAction(Flow flow) {
        ActionState terminateSession = this.createActionState(flow, "terminateSession", this.createEvaluateAction("terminateSessionAction"));
        this.createStateDefaultTransition(terminateSession, "gatewayRequestCheck");
    }

    protected void createDefaultEndStates(Flow flow) {
        this.createRedirectUnauthorizedServiceUrlEndState(flow);
        this.createServiceErrorEndState(flow);
        this.createRedirectEndState(flow);
        this.createPostEndState(flow);
        this.createHeaderEndState(flow);
        this.createGenericLoginSuccessEndState(flow);
        this.createServiceWarningViewState(flow);
    }

    protected void createRedirectEndState(Flow flow) {
        this.createEndState(flow, "redirectView", "requestScope.url", true);
    }

    protected void createPostEndState(Flow flow) {
        this.createEndState(flow, "postView", "casPostResponseView");
    }

    protected void createHeaderEndState(Flow flow) {
        EndState endState = this.createEndState(flow, "headerView");
        endState.setFinalResponseAction(this.createEvaluateAction("injectResponseHeadersAction"));
    }

    protected void createRedirectUnauthorizedServiceUrlEndState(Flow flow) {
        this.createEndState(flow, "viewRedirectToUnauthorizedUrlView", "flowScope.unauthorizedRedirectUrl", true);
    }

    private void createServiceErrorEndState(Flow flow) {
        this.createEndState(flow, "viewServiceErrorView", "casServiceErrorView");
    }

    private void createGenericLoginSuccessEndState(Flow flow) {
        EndState state = this.createEndState(flow, "viewGenericLoginSuccess", "casGenericSuccessView");
        state.getEntryActionList().add(this.createEvaluateAction("genericSuccessViewAction"));
    }

    protected void createServiceWarningViewState(Flow flow) {
        ViewState stateWarning = this.createViewState(flow, "showWarningView", "casConfirmView");
        this.createTransitionForState(stateWarning, "success", "finalizeWarning");
        ActionState finalizeWarn = this.createActionState(flow, "finalizeWarning", this.createEvaluateAction("serviceWarningAction"));
        this.createTransitionForState(finalizeWarn, "redirect", "redirect");
    }

    protected void createDefaultGlobalExceptionHandlers(Flow flow) {
        TransitionExecutingFlowExecutionExceptionHandler h = new TransitionExecutingFlowExecutionExceptionHandler();
        h.add(UnauthorizedSsoServiceException.class, "viewLoginForm");
        h.add(NoSuchFlowExecutionException.class, "viewServiceErrorView");
        h.add(UnauthorizedServiceException.class, "serviceUnauthorizedCheck");
        h.add(UnauthorizedServiceForPrincipalException.class, "serviceUnauthorizedCheck");
        flow.getExceptionHandlerSet().add(h);
    }

    protected void createDefaultDecisionStates(Flow flow) {
        this.createServiceUnauthorizedCheckDecisionState(flow);
        this.createServiceCheckDecisionState(flow);
        this.createWarnDecisionState(flow);
        this.createGatewayRequestCheckDecisionState(flow);
        this.createHasServiceCheckDecisionState(flow);
        this.createRenewCheckDecisionState(flow);
    }

    protected void createServiceUnauthorizedCheckDecisionState(Flow flow) {
        this.createDecisionState(flow, "serviceUnauthorizedCheck", "flowScope.unauthorizedRedirectUrl != null", "viewRedirectToUnauthorizedUrlView", "viewServiceErrorView");
    }

    protected void createServiceCheckDecisionState(Flow flow) {
        this.createDecisionState(flow, "serviceCheck", "flowScope.service != null", "generateServiceTicket", "viewGenericLoginSuccess");
    }

    protected void createWarnDecisionState(Flow flow) {
        this.createDecisionState(flow, "warn", "flowScope.warnCookieValue", "showWarningView", "redirect");
    }

    protected void createGatewayRequestCheckDecisionState(Flow flow) {
        this.createDecisionState(flow, "gatewayRequestCheck", "requestParameters.gateway != '' and requestParameters.gateway != null and flowScope.service != null", "gatewayServicesManagementCheck", "serviceAuthorizationCheck");
    }

    protected void createHasServiceCheckDecisionState(Flow flow) {
        this.createDecisionState(flow, "hasServiceCheck", "flowScope.service != null", "renewRequestCheck", "viewGenericLoginSuccess");
    }

    protected void createRenewCheckDecisionState(Flow flow) {
        String renewParam = "requestParameters.renew";
        this.createDecisionState(flow, "renewRequestCheck", "requestParameters.renew != '' and requestParameters.renew != null", "serviceAuthorizationCheck", "generateServiceTicket");
    }
}
