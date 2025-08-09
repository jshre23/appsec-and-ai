"""
Generates PDF and HTML reports summarizing detected attacks, blocked requests, and system performance.
"""
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os


class ReportGenerator:
    def __init__(self, shap_values=None, features=None, f1_score=None, attacks=None, blocked=None, performance=None,
                 X_train=None, y_train=None, X_test=None, y_test=None, model=None, df=None):
        self.shap_values = shap_values
        self.features = features
        self.f1_score = f1_score
        self.attacks = attacks
        self.blocked = blocked
        self.performance = performance
        self.X_train = X_train
        self.y_train = y_train
        self.X_test = X_test
        self.y_test = y_test
        self.model = model
        self.df = df

    def plot_f1_score(self, output_path='static/f1_score.png'):
        plt.figure(figsize=(4, 2))
        plt.bar(['F1 Score'], [self.f1_score], color='#3498db')
        plt.ylim(0, 1)
        plt.title('F1 Score')
        plt.savefig(output_path)
        plt.close()
        return output_path

    def plot_correlation_heatmap(self, output_path='static/corr_heatmap.png'):
        if self.df is not None:
            corr = self.df.corr(numeric_only=True)
            plt.figure(figsize=(8, 6))
            plt.imshow(corr, cmap='coolwarm', interpolation='nearest')
            plt.colorbar()
            plt.title('Feature Correlation Heatmap')
            plt.xticks(range(len(corr.columns)), corr.columns, rotation=90, fontsize=6)
            plt.yticks(range(len(corr.columns)), corr.columns, fontsize=6)
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
            return output_path
        return ''

    def plot_overfitting(self, output_path='static/overfitting.png'):
        if self.model is not None and self.X_train is not None and self.y_train is not None and self.X_test is not None and self.y_test is not None:
            from sklearn.metrics import accuracy_score
            train_acc = accuracy_score(self.y_train, self.model.predict(self.X_train))
            test_acc = accuracy_score(self.y_test, self.model.predict(self.X_test))
            plt.figure(figsize=(4, 2))
            plt.bar(['Train', 'Test'], [train_acc, test_acc], color=['#2ecc71', '#e74c3c'])
            plt.ylim(0, 1)
            plt.title('Overfitting (Accuracy)')
            plt.savefig(output_path)
            plt.close()
            return output_path
        return ''

    def generate_html_report(self, output_path):
        f1_img = self.plot_f1_score()
        corr_img = self.plot_correlation_heatmap()
        overfit_img = self.plot_overfitting()
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report_template.html')
        html_content = template.render(
            shap_values=self.shap_values,
            features=self.features,
            f1_score=self.f1_score,
            attacks=self.attacks,
            blocked=self.blocked,
            performance=self.performance,
            f1_img=f1_img,
            corr_img=corr_img,
            overfit_img=overfit_img
        )
        with open(output_path, 'w') as f:
            f.write(html_content)

    def generate_pdf_report(self, output_path):
        c = canvas.Canvas(output_path, pagesize=letter)
        c.drawString(100, 750, f"F1 Score: {self.f1_score}")
        c.drawString(100, 730, f"Detected Attacks: {self.attacks}")
        c.drawString(100, 710, f"Blocked Requests: {self.blocked}")
        c.drawString(100, 690, f"System Performance: {self.performance}")
        c.save()
