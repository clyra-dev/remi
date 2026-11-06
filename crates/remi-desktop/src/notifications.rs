//! Native macOS notifications via UserNotifications; all application code is Rust.
use block2::{DynBlock, RcBlock};
use objc2::{
    AnyThread, DefinedClass, define_class, msg_send,
    rc::Retained,
    runtime::{Bool, ProtocolObject},
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString};
use objc2_user_notifications::*;
use std::{
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use tracing::{info, warn};

pub struct Callbacks {
    clicked: Arc<Mutex<Option<String>>>,
    context: eframe::egui::Context,
}
define_class!(
    #[unsafe(super(NSObject))]
    #[name = "RemiNotificationDelegate"]
    #[ivars = Callbacks]
    pub struct Delegate;
    unsafe impl NSObjectProtocol for Delegate {}
    unsafe impl UNUserNotificationCenterDelegate for Delegate {
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            completion: &DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            completion.call((UNNotificationPresentationOptions::Banner
                | UNNotificationPresentationOptions::List
                | UNNotificationPresentationOptions::Sound,));
        }
        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn clicked(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            completion: &DynBlock<dyn Fn()>,
        ) {
            let id = response.notification().request().identifier().to_string();
            if let Ok(mut slot) = self.ivars().clicked.lock() {
                *slot = Some(id);
            }
            self.ivars().context.request_repaint();
            self.ivars()
                .context
                .send_viewport_cmd(eframe::egui::ViewportCommand::Visible(true));
            self.ivars()
                .context
                .send_viewport_cmd(eframe::egui::ViewportCommand::Focus);
            completion.call(());
        }
    }
);

pub struct Notifications {
    center: Retained<UNUserNotificationCenter>,
    _delegate: Retained<Delegate>,
    /// 0 unknown, 1 not requested, 2 denied, 3 authorized, 4 delivery error.
    pub status: Arc<AtomicU8>,
    pub clicked: Arc<Mutex<Option<String>>>,
    context: eframe::egui::Context,
}
impl Notifications {
    pub fn new(context: eframe::egui::Context) -> Self {
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let clicked = Arc::new(Mutex::new(None));
        let allocated = Delegate::alloc().set_ivars(Callbacks {
            clicked: clicked.clone(),
            context: context.clone(),
        });
        // SAFETY: initialize our own NSObject subclass exactly once, retaining it for the lifetime of the center delegate.
        let delegate: Retained<Delegate> = unsafe { msg_send![super(allocated), init] };
        center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        let result = Self {
            center,
            _delegate: delegate,
            status: Arc::new(AtomicU8::new(0)),
            clicked,
            context,
        };
        result.refresh();
        result
    }
    pub fn refresh(&self) {
        let status = self.status.clone();
        let ctx = self.context.clone();
        let callback = RcBlock::new(move |settings: NonNull<UNNotificationSettings>| {
            // SAFETY: Apple supplies a valid object for the callback duration.
            let authorization = unsafe { settings.as_ref() }.authorizationStatus();
            let value = if authorization == UNAuthorizationStatus::NotDetermined {
                1
            } else if authorization == UNAuthorizationStatus::Denied {
                2
            } else {
                3
            };
            status.store(value, Ordering::Relaxed);
            ctx.request_repaint();
        });
        self.center
            .getNotificationSettingsWithCompletionHandler(&callback);
    }
    pub fn request(&self) {
        let status = self.status.clone();
        let ctx = self.context.clone();
        let callback = RcBlock::new(move |granted: Bool, error: *mut NSError| {
            status.store(
                if !error.is_null() {
                    4
                } else if granted.as_bool() {
                    3
                } else {
                    2
                },
                Ordering::Relaxed,
            );
            info!(
                action = "notification_authorization",
                granted = granted.as_bool()
            );
            // SAFETY: the optional NSError is valid for this callback's duration.
            if let Some(error) = unsafe { error.as_ref() } {
                warn!(action = "notification_permission_error", domain = %error.domain(), code = error.code());
            }
            ctx.request_repaint();
        });
        self.center
            .requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
                &callback,
            );
    }
    pub fn send(&self, id: &str, title: &str, body: &str) -> bool {
        if self.status.load(Ordering::Relaxed) != 3 {
            return false;
        }
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(title));
        content.setBody(&NSString::from_str(body));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(id),
            &content,
            None,
        );
        let status = self.status.clone();
        let ctx = self.context.clone();
        let callback = RcBlock::new(move |error: *mut NSError| {
            if error.is_null() {
                info!(action = "notification_enqueued");
            } else {
                status.store(4, Ordering::Relaxed);
                warn!(action = "notification_failed");
            }
            ctx.request_repaint();
        });
        self.center
            .addNotificationRequest_withCompletionHandler(&request, Some(&callback));
        true
    }
}
